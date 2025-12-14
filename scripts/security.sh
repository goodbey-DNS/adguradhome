#!/bin/bash
# AdGuardHome 自动更新工作流安全配置和验证函数

set -euo pipefail

# =============================================================================
# 安全配置
# =============================================================================

# 允许的域名白名单
readonly ALLOWED_DOMAINS=(
    "github.com"
    "api.github.com"
    "objects.githubusercontent.com"
)

# 允许的文件类型
readonly ALLOWED_FILE_TYPES=(
    "application/gzip"
    "application/x-gzip"
    "application/octet-stream"
)

# 最大文件大小 (50MB)
readonly MAX_FILE_SIZE=52428800

# 速率限制配置
readonly MAX_API_CALLS_PER_MINUTE=30
readonly API_CALL_DELAY=2

# =============================================================================
# 安全验证函数
# =============================================================================

# 验证URL安全性
validate_url_security() {
    local url="$1"
    
    # 提取域名
    local domain
    domain=$(echo "$url" | sed -n 's|https\?://\([^/]*\).*|\1|p')
    
    # 检查域名是否在白名单中
    local allowed=false
    for allowed_domain in "${ALLOWED_DOMAINS[@]}"; do
        if [[ "$domain" == *"$allowed_domain"* ]]; then
            allowed=true
            break
        fi
    done
    
    if [[ "$allowed" != "true" ]]; then
        echo "Error: Domain '$domain' is not in allowed list"
        return 1
    fi
    
    # 检查URL协议
    if [[ ! "$url" =~ ^https:// ]]; then
        echo "Error: Only HTTPS URLs are allowed"
        return 1
    fi
    
    # 检查可疑路径
    if [[ "$url" =~ \.\. ]] || [[ "$url" =~ %[0-9a-fA-F]{2} ]]; then
        echo "Error: Suspicious URL path detected"
        return 1
    fi
    
    return 0
}

# 验证文件路径安全性
validate_file_path() {
    local file_path="$1"
    local base_dir="${2:-/tmp}"
    
    # 规范化路径
    local real_path
    real_path=$(realpath "$file_path" 2>/dev/null || echo "$file_path")
    local real_base_dir
    real_base_dir=$(realpath "$base_dir" 2>/dev/null || echo "$base_dir")
    
    # 检查路径是否在允许的目录内
    if [[ ! "$real_path" == "$real_base_dir"* ]]; then
        echo "Error: File path '$file_path' is outside allowed directory"
        return 1
    fi
    
    # 检查路径遍历攻击
    if [[ "$file_path" =~ \.\./ ]] || [[ "$file_path" =~ \~ ]]; then
        echo "Error: Path traversal characters detected in '$file_path'"
        return 1
    fi
    
    return 0
}

# 验证文件类型和大小
validate_file_security() {
    local file="$1"
    local max_size="${2:-$MAX_FILE_SIZE}"
    
    # 验证文件路径
    if ! validate_file_path "$file"; then
        return 1
    fi
    
    # 检查文件存在
    if [[ ! -f "$file" ]]; then
        echo "Error: File '$file' does not exist"
        return 1
    fi
    
    # 检查文件大小
    local actual_size
    actual_size=$(stat -c%s "$file" 2>/dev/null || echo "0")
    if [[ $actual_size -gt $max_size ]]; then
        echo "Error: File size $actual_size exceeds maximum $max_size"
        return 1
    fi
    
    # 检查文件类型（如果file命令可用）
    if command -v file >/dev/null 2>&1; then
        local file_type
        file_type=$(file --brief --mime-type "$file" 2>/dev/null || echo "")
        
        if [[ -n "$file_type" ]]; then
            local type_allowed=false
            for allowed_type in "${ALLOWED_FILE_TYPES[@]}"; do
                if [[ "$file_type" == "$allowed_type" ]]; then
                    type_allowed=true
                    break
                fi
            done
            
            if [[ "$type_allowed" != "true" ]]; then
                echo "Error: File type '$file_type' is not allowed"
                return 1
            fi
        fi
    fi
    
    return 0
}

# 验证JSON响应安全性
validate_json_security() {
    local json_file="$1"
    
    # 基本JSON验证
    if ! validate_json_response "$json_file"; then
        return 1
    fi
    
    # 检查JSON大小
    local json_size
    json_size=$(stat -c%s "$json_file" 2>/dev/null || echo "0")
    if [[ $json_size -gt 1048576 ]]; then  # 1MB limit
        echo "Error: JSON response too large: $json_size bytes"
        return 1
    fi
    
    # 检查可疑内容
    if grep -q "<script\|javascript:\|data:" "$json_file" 2>/dev/null; then
        echo "Error: Suspicious content detected in JSON response"
        return 1
    fi
    
    return 0
}

# =============================================================================
# 安全的API调用函数
# =============================================================================

# 安全的curl函数
secure_curl() {
    local url="$1"
    local output="$2"
    local max_time="${3:-$DEFAULT_TIMEOUT}"
    
    # 验证URL安全性
    if ! validate_url_security "$url"; then
        return 1
    fi
    
    # 验证输出路径
    if ! validate_file_path "$output"; then
        return 1
    fi
    
    # 使用安全的curl选项
    curl -s -L \
        --max-time "$max_time" \
        --retry 2 \
        --retry-delay 3 \
        --user-agent "AdGuardHome-Update-Workflow/1.0" \
        --connect-timeout 10 \
        -o "$output" \
        "$url" 2>/dev/null || {
        echo "Error: Secure curl failed"
        return 1
    }
    
    return 0
}

# 带速率限制的安全重试函数
secure_retry_with_backoff() {
    local max_attempts=3
    local base_delay=5
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        # 添加API调用延迟
        if [[ $attempt -gt 1 ]]; then
            sleep $API_CALL_DELAY
        fi
        
        if "$@"; then
            return 0
        fi
        
        if [ $attempt -lt $max_attempts ]; then
            local delay=$((base_delay * (2**(attempt-1))))
            echo "Attempt $attempt failed, retrying in ${delay}s..."
            sleep $delay
        fi
        
        ((attempt++))
    done
    
    return 1
}

# =============================================================================
# 环境安全检查
# =============================================================================

# 检查运行环境安全性
check_environment_security() {
    # 检查是否在安全的环境中运行
    if [[ -z "${GITHUB_ACTIONS:-}" ]]; then
        echo "Warning: Not running in GitHub Actions environment"
    fi
    
    # 检查敏感环境变量
    local sensitive_vars=("GITHUB_TOKEN" "API_TOKEN" "SECRET_KEY")
    for var in "${sensitive_vars[@]}"; do
        if [[ -n "${!var:-}" ]]; then
            echo "Info: Sensitive variable $var is set"
        fi
    done
    
    # 检查磁盘空间
    local available_space
    available_space=$(df /tmp 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")
    if [[ $available_space -lt 1048576 ]]; then  # 1GB
        echo "Warning: Low disk space in /tmp: ${available_space}KB"
    fi
    
    return 0
}

# =============================================================================
# 安全清理函数
# =============================================================================

# 安全清理函数
secure_cleanup() {
    local temp_dir="${1:-/tmp}"
    
    # 清理临时文件，但只清理我们创建的文件
    local patterns=(
        "$temp_dir/latest_release*.json"
        "$temp_dir/current_release*.json"
        "$temp_dir/AdGuardHome_*.tar.gz"
        "$temp_dir/adguard_update.lock"
    )
    
    for pattern in "${patterns[@]}"; do
        if compgen -G "$pattern" > /dev/null 2>&1; then
            rm -f $pattern 2>/dev/null || true
        fi
    done
    
    log_update_event "INFO" "Secure cleanup completed"
    return 0
}

# =============================================================================
# 初始化安全环境
# =============================================================================

# 初始化安全环境
init_secure_environment() {
    # 检查环境安全
    check_environment_security
    
    # 设置安全的umask
    umask 077
    
    # 确保在失败时进行安全清理
    trap 'release_lock; secure_cleanup' EXIT
    
    # 获取锁
    if ! acquire_lock; then
        log_update_event "ERROR" "Failed to acquire lock, exiting"
        exit 1
    fi
    
    log_update_event "INFO" "Secure environment initialized"
    return 0
}

# =============================================================================
# 主函数入口
# =============================================================================

# 如果直接执行此脚本，显示帮助信息
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "AdGuardHome Update Security Functions"
    echo "Usage: source security.sh"
    echo ""
    echo "Available functions:"
    echo "  validate_url_security <url>"
    echo "  validate_file_path <file_path> [base_dir]"
    echo "  validate_file_security <file> [max_size]"
    echo "  validate_json_security <json_file>"
    echo "  secure_curl <url> <output> [timeout]"
    echo "  secure_retry_with_backoff <command>"
    echo "  check_environment_security"
    echo "  secure_cleanup [temp_dir]"
    echo "  init_secure_environment"
fi