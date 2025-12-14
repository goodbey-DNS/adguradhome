#!/bin/bash
# AdGuardHome 自动更新工作流配置管理脚本

set -euo pipefail

# =============================================================================
# 配置变量
# =============================================================================

# 默认配置文件路径
readonly DEFAULT_CONFIG_FILE="./config/settings.yml"
readonly CURRENT_ENV="${ENVIRONMENT:-production}"

# 全局配置变量
GITHUB_API_BASE=""
ADGUARD_REPO=""
DEFAULT_TIMEOUT=""
DOWNLOAD_TIMEOUT=""
MAX_FILE_SIZE=""
MIN_FILE_SIZE=""
TEMP_DIR=""
LOCK_FILE=""
ALLOWED_DOMAINS=()
ALLOWED_MIME_TYPES=()
MAX_API_CALLS_PER_MINUTE=""
API_CALL_DELAY=""
LOCK_TIMEOUT=""
LOCK_MAX_WAIT=""
LOCK_CHECK_INTERVAL=""

# =============================================================================
# 配置加载函数
# =============================================================================

# 使用yq工具读取YAML配置（如果可用）
load_config_with_yq() {
    local config_file="$1"
    local section="$2"
    local key="$3"
    local default_value="$4"
    
    if command -v yq >/dev/null 2>&1; then
        yq eval ".${section}.${key} // \"${default_value}\"" "$config_file" 2>/dev/null || echo "$default_value"
    else
        echo "$default_value"
    fi
}

# 使用grep和sed读取YAML配置（备用方案）
load_config_with_grep() {
    local config_file="$1"
    local section="$2"
    local key="$3"
    local default_value="$4"
    
    local pattern="^${key}:"
    local value
    
    value=$(grep -A 20 "^${section}:" "$config_file" | grep "$pattern" | head -1 | cut -d':' -f2- | sed 's/^["'\''']//' | sed 's/["'\''']$//' | tr -d ' ' || echo "$default_value")
    
    if [[ -z "$value" ]]; then
        echo "$default_value"
    else
        echo "$value"
    fi
}

# 加载配置值
load_config_value() {
    local section="$1"
    local key="$2"
    local default_value="$3"
    local config_file="${4:-$DEFAULT_CONFIG_FILE}"
    
    # 检查配置文件是否存在
    if [[ ! -f "$config_file" ]]; then
        echo "$default_value"
        return
    fi
    
    # 优先使用yq，回退到grep
    local value
    value=$(load_config_with_yq "$config_file" "$section" "$key" "$default_value")
    
    if [[ "$value" == "$default_value" ]] && command -v yq >/dev/null 2>&1; then
        value=$(load_config_with_grep "$config_file" "$section" "$key" "$default_value")
    fi
    
    echo "$value"
}

# 加载数组配置
load_config_array() {
    local section="$1"
    local key="$2"
    local config_file="${3:-$DEFAULT_CONFIG_FILE}"
    
    if [[ ! -f "$config_file" ]]; then
        return 1
    fi
    
    # 使用yq读取数组
    if command -v yq >/dev/null 2>&1; then
        yq eval ".${section}.${key}[]" "$config_file" 2>/dev/null || return 1
    else
        # 使用grep和sed读取数组（简化实现）
        grep -A 50 "^${section}:" "$config_file" | grep -A 20 "^${key}:" | grep "^-" | sed 's/^["'\''']//' | sed 's/["'\''']$//' | tr -d ' ' || return 1
    fi
}

# =============================================================================
# 配置初始化函数
# =============================================================================

# 初始化全局配置变量
init_config_variables() {
    local config_file="${1:-$DEFAULT_CONFIG_FILE}"
    
    # API配置
    GITHUB_API_BASE=$(load_config_value "api" "base_url" "https://api.github.com" "$config_file")
    ADGUARD_REPO=$(load_config_value "api" "adguard_repo" "AdguardTeam/AdGuardHome" "$config_file")
    DEFAULT_TIMEOUT=$(load_config_value "api" "default_timeout" "10" "$config_file")
    DOWNLOAD_TIMEOUT=$(load_config_value "api" "download_timeout" "300" "$config_file")
    
    # 文件配置
    MAX_FILE_SIZE=$(load_config_value "files" "max_file_size" "52428800" "$config_file")
    MIN_FILE_SIZE=$(load_config_value "files" "min_file_size" "10000000" "$config_file")
    TEMP_DIR=$(load_config_value "files" "temp_dir" "/tmp" "$config_file")
    LOCK_FILE=$(load_config_value "files" "lock_file" "/tmp/adguard_update.lock" "$config_file")
    
    # 安全配置
    MAX_API_CALLS_PER_MINUTE=$(load_config_value "security" "max_api_calls_per_minute" "30" "$config_file")
    API_CALL_DELAY=$(load_config_value "security" "api_call_delay" "2" "$config_file")
    LOCK_TIMEOUT=$(load_config_value "security" "lock_timeout" "1800" "$config_file")
    LOCK_MAX_WAIT=$(load_config_value "security" "lock_max_wait" "300" "$config_file")
    LOCK_CHECK_INTERVAL=$(load_config_value "security" "lock_check_interval" "5" "$config_file")
    
    # 加载域名白名单
    ALLOWED_DOMAINS=()
    while IFS= read -r domain; do
        if [[ -n "$domain" ]]; then
            ALLOWED_DOMAINS+=("$domain")
        fi
    done < <(load_config_array "security" "allowed_domains" "$config_file")
    
    # 如果没有加载到域名，使用默认值
    if [[ ${#ALLOWED_DOMAINS[@]} -eq 0 ]]; then
        ALLOWED_DOMAINS=("github.com" "api.github.com" "objects.githubusercontent.com")
    fi
    
    # 加载允许的MIME类型
    ALLOWED_MIME_TYPES=()
    while IFS= read -r mime_type; do
        if [[ -n "$mime_type" ]]; then
            ALLOWED_MIME_TYPES+=("$mime_type")
        fi
    done < <(load_config_array "security" "allowed_mime_types" "$config_file")
    
    # 如果没有加载到MIME类型，使用默认值
    if [[ ${#ALLOWED_MIME_TYPES[@]} -eq 0 ]]; then
        ALLOWED_MIME_TYPES=("application/gzip" "application/x-gzip" "application/octet-stream")
    fi
    
    return 0
}

# =============================================================================
# 配置验证函数
# =============================================================================

# 验证配置值
validate_config() {
    local errors=0
    
    # 验证API配置
    if [[ -z "$GITHUB_API_BASE" ]]; then
        echo "Error: GITHUB_API_BASE is not configured"
        ((errors++))
    fi
    
    if [[ -z "$ADGUARD_REPO" ]]; then
        echo "Error: ADGUARD_REPO is not configured"
        ((errors++))
    fi
    
    # 验证超时配置
    if ! [[ "$DEFAULT_TIMEOUT" =~ ^[0-9]+$ ]]; then
        echo "Error: DEFAULT_TIMEOUT must be a number"
        ((errors++))
    fi
    
    if ! [[ "$DOWNLOAD_TIMEOUT" =~ ^[0-9]+$ ]]; then
        echo "Error: DOWNLOAD_TIMEOUT must be a number"
        ((errors++))
    fi
    
    # 验证文件大小配置
    if ! [[ "$MAX_FILE_SIZE" =~ ^[0-9]+$ ]]; then
        echo "Error: MAX_FILE_SIZE must be a number"
        ((errors++))
    fi
    
    if ! [[ "$MIN_FILE_SIZE" =~ ^[0-9]+$ ]]; then
        echo "Error: MIN_FILE_SIZE must be a number"
        ((errors++))
    fi
    
    # 验证目录配置
    if [[ -z "$TEMP_DIR" ]]; then
        echo "Error: TEMP_DIR is not configured"
        ((errors++))
    fi
    
    if [[ -z "$LOCK_FILE" ]]; then
        echo "Error: LOCK_FILE is not configured"
        ((errors++))
    fi
    
    # 验证数组配置
    if [[ ${#ALLOWED_DOMAINS[@]} -eq 0 ]]; then
        echo "Error: ALLOWED_DOMAINS is empty"
        ((errors++))
    fi
    
    if [[ ${#ALLOWED_MIME_TYPES[@]} -eq 0 ]]; then
        echo "Error: ALLOWED_MIME_TYPES is empty"
        ((errors++))
    fi
    
    return $errors
}

# =============================================================================
# 配置显示函数
# =============================================================================

# 显示当前配置
show_config() {
    echo "=== AdGuardHome Update Configuration ==="
    echo "Environment: $CURRENT_ENV"
    echo ""
    echo "API Configuration:"
    echo "  GITHUB_API_BASE: $GITHUB_API_BASE"
    echo "  ADGUARD_REPO: $ADGUARD_REPO"
    echo "  DEFAULT_TIMEOUT: $DEFAULT_TIMEOUT"
    echo "  DOWNLOAD_TIMEOUT: $DOWNLOAD_TIMEOUT"
    echo ""
    echo "File Configuration:"
    echo "  MAX_FILE_SIZE: $MAX_FILE_SIZE"
    echo "  MIN_FILE_SIZE: $MIN_FILE_SIZE"
    echo "  TEMP_DIR: $TEMP_DIR"
    echo "  LOCK_FILE: $LOCK_FILE"
    echo ""
    echo "Security Configuration:"
    echo "  MAX_API_CALLS_PER_MINUTE: $MAX_API_CALLS_PER_MINUTE"
    echo "  API_CALL_DELAY: $API_CALL_DELAY"
    echo "  LOCK_TIMEOUT: $LOCK_TIMEOUT"
    echo "  LOCK_MAX_WAIT: $LOCK_MAX_WAIT"
    echo "  LOCK_CHECK_INTERVAL: $LOCK_CHECK_INTERVAL"
    echo "  ALLOWED_DOMAINS: ${ALLOWED_DOMAINS[*]}"
    echo "  ALLOWED_MIME_TYPES: ${ALLOWED_MIME_TYPES[*]}"
    echo "=========================================="
}

# =============================================================================
# 环境配置覆盖函数
# =============================================================================

# 应用环境特定配置
apply_environment_config() {
    local env="$1"
    local config_file="${2:-$DEFAULT_CONFIG_FILE}"
    
    if [[ -z "$env" ]]; then
        return 0
    fi
    
    # 日志级别
    local log_level
    log_level=$(load_config_value "environments.${env}" "level" "INFO" "$config_file")
    export LOG_LEVEL="$log_level"
    
    # 详细日志
    local verbose
    verbose=$(load_config_value "environments.${env}" "verbose" "false" "$config_file")
    export VERBOSE_LOGGING="$verbose"
    
    # API调用频率限制
    local api_calls
    api_calls=$(load_config_value "environments.${env}" "max_api_calls_per_minute" "$MAX_API_CALLS_PER_MINUTE" "$config_file")
    if [[ "$api_calls" != "$MAX_API_CALLS_PER_MINUTE" ]]; then
        MAX_API_CALLS_PER_MINUTE="$api_calls"
    fi
    
    local api_delay
    api_delay=$(load_config_value "environments.${env}" "api_call_delay" "$API_CALL_DELAY" "$config_file")
    if [[ "$api_delay" != "$API_CALL_DELAY" ]]; then
        API_CALL_DELAY="$api_delay"
    fi
    
    return 0
}

# =============================================================================
# 主初始化函数
# =============================================================================

# 初始化配置系统
init_config_system() {
    local config_file="${1:-$DEFAULT_CONFIG_FILE}"
    
    # 检查配置文件是否存在
    if [[ ! -f "$config_file" ]]; then
        echo "Warning: Configuration file $config_file not found, using defaults"
        # 使用默认值初始化
        init_config_variables "/dev/null"
    else
        # 加载配置
        init_config_variables "$config_file"
    fi
    
    # 应用环境特定配置
    apply_environment_config "$CURRENT_ENV" "$config_file"
    
    # 验证配置
    if ! validate_config; then
        echo "Error: Configuration validation failed"
        return 1
    fi
    
    # 如果启用详细日志，显示配置
    if [[ "${VERBOSE_LOGGING:-false}" == "true" ]]; then
        show_config
    fi
    
    return 0
}

# =============================================================================
# 主函数入口
# =============================================================================

# 如果直接执行此脚本，显示配置信息
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "AdGuardHome Update Configuration Manager"
    echo "======================================="
    
    # 初始化配置系统
    if init_config_system "$@"; then
        echo "Configuration loaded successfully"
        echo ""
        show_config
    else
        echo "Failed to load configuration"
        exit 1
    fi
fi