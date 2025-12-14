#!/bin/bash
# AdGuardHome 自动更新工作流共享函数库
# 包含版本验证、重试机制、API调用等通用功能

set -euo pipefail

# =============================================================================
# 配置变量
# =============================================================================

# API配置
readonly GITHUB_API_BASE="https://api.github.com"
readonly ADGUARD_REPO="AdguardTeam/AdGuardHome"
readonly MAX_FILE_SIZE=10000000  # 10MB
readonly DEFAULT_TIMEOUT=10
readonly DOWNLOAD_TIMEOUT=300

# =============================================================================
# 版本管理函数
# =============================================================================

# 版本验证函数
validate_version() {
    local version="$1"
    # 移除可能的v前缀
    version=$(echo "$version" | sed 's/^v//')
    if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Error: Invalid version format: $version"
        return 1
    fi
    return 0
}

# 清理版本号函数（移除v前缀）
clean_version() {
    local version="$1"
    [[ -n "$version" ]] && echo "$version" | sed 's/^v//' || echo ""
}

# 语义化版本比较
compare_versions() {
    local version1="$1"
    local version2="$2"
    
    # 清理版本号
    version1=$(clean_version "$version1")
    version2=$(clean_version "$version2")
    
    # 验证版本格式
    if ! validate_version "$version1" || ! validate_version "$version2"; then
        return 1
    fi
    
    # 将版本号转换为数组进行比较
    IFS='.' read -ra v1 <<< "$version1"
    IFS='.' read -ra v2 <<< "$version2"
    
    # 比较主版本、次版本、修订版本
    for i in {0..2}; do
        local num1=${v1[$i]:-0}
        local num2=${v2[$i]:-0}
        
        if (( num1 > num2 )); then
            echo "greater"
            return 0
        elif (( num1 < num2 )); then
            echo "less"
            return 0
        fi
    done
    
    echo "equal"
    return 0
}

# =============================================================================
# 重试机制函数
# =============================================================================

# 指数退避重试函数
retry_with_backoff() {
    local max_attempts=3
    local base_delay=5
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
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
# API处理函数
# =============================================================================

# API错误处理函数
handle_api_error() {
    local response_code="$1"
    
    case "$response_code" in
        403|429)
            echo "Rate limit exceeded. Waiting before retry..."
            return 2
            ;;
        404)
            echo "Resource not found"
            return 1
            ;;
        5*)
            echo "Server error, will retry"
            return 2
            ;;
        *)
            echo "Unexpected error: $response_code"
            return 1
            ;;
    esac
}

# 增强的curl函数，包含重试和错误处理
curl_with_retry() {
    local url="$1"
    local output="$2"
    local max_time="${3:-$DEFAULT_TIMEOUT}"
    
    # 确保输出目录存在
    local output_dir=$(dirname "$output")
    mkdir -p "$output_dir" 2>/dev/null || {
        echo "Error: Cannot create output directory"
        return 1
    }
    
    # 使用curl下载并获取状态码
    local response_code
    response_code=$(curl -s -L -w "%{http_code}" \
        --max-time "$max_time" \
        --retry 2 \
        --retry-delay 3 \
        -o "$output" \
        "$url" 2>/dev/null || echo "000")
    
    if [[ $response_code -ge 400 ]] || [[ $response_code == "000" ]]; then
        handle_api_error "$response_code"
        return $?
    fi
    
    return 0
}

# 获取最新版本信息
get_latest_version() {
    local output_file="$1"
    
    if ! retry_with_backoff curl_with_retry \
        "$GITHUB_API_BASE/repos/$ADGUARD_REPO/releases/latest" \
        "$output_file" "$DEFAULT_TIMEOUT"; then
        log_update_event "ERROR" "Failed to fetch latest version after retries"
        return 1
    fi
    
    # 验证文件
    if [[ ! -f "$output_file" ]] || [[ ! -s "$output_file" ]]; then
        log_update_event "ERROR" "Invalid response file"
        return 1
    fi
    
    # 验证JSON格式
    if ! jq empty "$output_file" 2>/dev/null; then
        log_update_event "ERROR" "Invalid JSON response"
        return 1
    fi
    
    return 0
}

# =============================================================================
# 文件处理函数
# =============================================================================

# 文件完整性验证函数
verify_file_integrity() {
    local file="$1"
    local expected_size="${2:-$MAX_FILE_SIZE}"
    
    # 检查文件存在
    if [[ ! -f "$file" ]]; then
        echo "Error: File $file does not exist"
        return 1
    fi
    
    # 检查文件大小
    local actual_size
    actual_size=$(stat -c%s "$file" 2>/dev/null || echo "0")
    if [[ $actual_size -lt $expected_size ]]; then
        echo "Error: File too small: $actual_size bytes (expected at least $expected_size)"
        return 1
    fi
    
    # 计算并验证SHA-256
    if command -v sha256sum >/dev/null 2>&1; then
        local sha256_hash
        sha256_hash=$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1 || echo "")
        if [[ -n "$sha256_hash" ]]; then
            echo "File SHA-256: $sha256_hash"
        fi
    fi
    
    return 0
}

# =============================================================================
# 并发控制函数
# =============================================================================

# 并发控制锁机制
acquire_lock() {
    local lock_file="/tmp/adguard_update.lock"
    local max_wait=300
    local wait_interval=5
    local waited=0
    
    while [[ -f "$lock_file" ]]; do
        # 检查锁文件是否过期（超过30分钟）
        if [[ -f "$lock_file" ]]; then
            local lock_age=$(($(date +%s) - $(stat -c%Y "$lock_file" 2>/dev/null || echo "0")))
            if [[ $lock_age -gt 1800 ]]; then
                echo "Lock file is stale, removing..."
                rm -f "$lock_file" 2>/dev/null || true
                break
            fi
        fi
        
        if [[ $waited -ge $max_wait ]]; then
            echo "Error: Another update process is running"
            return 1
        fi
        
        echo "Waiting for lock... ($waited/$max_wait)"
        sleep $wait_interval
        ((waited+=wait_interval))
    done
    
    echo $$ > "$lock_file" 2>/dev/null || {
        echo "Error: Cannot create lock file"
        return 1
    }
    return 0
}

release_lock() {
    rm -f "/tmp/adguard_update.lock" 2>/dev/null || true
}

# =============================================================================
# 日志记录函数
# =============================================================================

# 日志记录函数
log_update_event() {
    local event="$1"
    local details="$2"
    local timestamp
    timestamp=$(date -u '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || echo "TIMESTAMP_ERROR")
    
    echo "[$timestamp] $event: $details"
}

# =============================================================================
# 输入验证函数
# =============================================================================

# 验证JSON响应
validate_json_response() {
    local json_file="$1"
    local required_field="$2"
    
    # 检查文件存在和格式
    if [[ ! -f "$json_file" ]] || [[ ! -s "$json_file" ]]; then
        echo "Error: JSON file does not exist or is empty"
        return 1
    fi
    
    # 验证JSON格式
    if ! jq empty "$json_file" 2>/dev/null; then
        echo "Error: Invalid JSON format"
        return 1
    fi
    
    # 验证必需字段
    if [[ -n "$required_field" ]]; then
        local field_value
        field_value=$(jq -r ".$required_field" "$json_file" 2>/dev/null || echo "")
        if [[ -z "$field_value" ]] || [[ "$field_value" == "null" ]]; then
            echo "Error: Required field '$required_field' is missing or null"
            return 1
        fi
    fi
    
    return 0
}

# =============================================================================
# 清理函数
# =============================================================================

# 清理临时文件
cleanup_temp_files() {
    local temp_dir="${1:-/tmp}"
    rm -f "$temp_dir"/*.json "$temp_dir"/*.tar.gz 2>/dev/null || true
    log_update_event "INFO" "Temporary files cleaned up"
}

# =============================================================================
# 初始化函数
# =============================================================================

# 初始化环境
init_environment() {
    # 确保在失败时释放锁
    trap 'release_lock; cleanup_temp_files' EXIT
    
    # 获取锁
    if ! acquire_lock; then
        log_update_event "ERROR" "Failed to acquire lock, exiting"
        exit 1
    fi
    
    log_update_event "INFO" "Environment initialized successfully"
    return 0
}

# =============================================================================
# 主函数入口
# =============================================================================

# 如果直接执行此脚本，显示帮助信息
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "AdGuardHome Update Common Functions Library"
    echo "Usage: source common.sh"
    echo ""
    echo "Available functions:"
    echo "  validate_version <version>"
    echo "  clean_version <version>"
    echo "  compare_versions <version1> <version2>"
    echo "  retry_with_backoff <command>"
    echo "  curl_with_retry <url> <output> [timeout]"
    echo "  get_latest_version <output_file>"
    echo "  verify_file_integrity <file> [expected_size]"
    echo "  acquire_lock"
    echo "  release_lock"
    echo "  log_update_event <event> <details>"
    echo "  validate_json_response <json_file> [required_field]"
    echo "  cleanup_temp_files [temp_dir]"
    echo "  init_environment"
fi