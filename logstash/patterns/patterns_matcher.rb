#==============================================================================
# 2SeC SIEM - Attack Pattern Matcher Engine
# YAML 기반 고성능 공격 탐지 엔진
#==============================================================================

require 'yaml'
require 'ipaddr'

class AttackPatternMatcher
  
  # 신뢰도 계산 상수
  DEFAULT_BASE_CONFIDENCE = 0.7
  PATTERN_LENGTH_DIVISOR = 20.0
  COMPLEXITY_MULTIPLIER = 0.2
  MAX_COMPLEXITY_BONUS = 0.3
  SUSPICIOUS_CHAR_MULTIPLIER = 0.05
  MAX_SUSPICIOUS_BONUS = 0.2
  CONFIG_CHECK_INTERVAL = 30  # 30초마다 설정 파일 체크
  
  def initialize(pattern_file, severity_file)
    # 파일 경로 저장
    @pattern_file = pattern_file
    @severity_file = severity_file

    # YAML 내용을 저장할 변수들 (초기값 nil)
    @pattern_config = nil
    @severity_config = nil

    # 처리된 데이터를 저장할 변수들 (초기값 빈 컨테이너)  
    @compiled_patterns = {}
    @whitelist_ips = []

    # 파일 변경 감지용 변수들
    @last_pattern_modified = nil
    @last_severity_modified = nil
    @last_config_check = Time.now
    
    load_configurations     # 실제 파일 읽기 및 초기화
  end
  
  #---------------------------------------------------------------------------
  # 설정 파일 로드 및 리로드
  #---------------------------------------------------------------------------
  
  def load_configurations
    # 파일 변경 감지 후 리로드
    pattern_mtime = File.mtime(@pattern_file)
    severity_mtime = File.mtime(@severity_file)
    
    if @last_pattern_modified.nil? || pattern_mtime > @last_pattern_modified
      load_pattern_config
      @last_pattern_modified = pattern_mtime
    end
    
    if @last_severity_modified.nil? || severity_mtime > @last_severity_modified  
      load_severity_config
      @last_severity_modified = severity_mtime
    end
    
    compile_patterns if @pattern_config && @severity_config
  end
  
  def check_configurations
    load_configurations
    @last_config_check = Time.now
  end
  
  def load_pattern_config
    begin
      @pattern_config = YAML.load_file(@pattern_file)
      puts "[INFO] Pattern config loaded: #{@pattern_config['metadata']['version']}"
    rescue => e
      puts "[ERROR] Failed to load pattern config: #{e.message}"
      @pattern_config = default_pattern_config
    end
  end
  
  def load_severity_config  
    begin
      @severity_config = YAML.load_file(@severity_file)
      puts "[INFO] Severity config loaded: #{@severity_config['metadata']['version']}"
    rescue => e
      puts "[ERROR] Failed to load severity config: #{e.message}"
      @severity_config = default_severity_config
    end
  end
  
  #---------------------------------------------------------------------------
  # 패턴 컴파일 (정규식으로 변환)
  #---------------------------------------------------------------------------
  
  def compile_patterns
    @compiled_patterns = {}
    
    return unless @pattern_config&.dig('attack_patterns')  
    
    @pattern_config['attack_patterns'].each do |attack_type, config|
      # 비활성화된 공격 타입은 건너뛰기
      next unless config['enabled']
      
      # 심각도 매핑에서 해당 공격의 심각도 가져오기
      severity = @severity_config.dig('attack_severity', attack_type) || 'info'
      
      @compiled_patterns[attack_type] = {
        'severity' => severity,
        'description' => config['description'],
        'techniques' => {}
      }
      
      # 각 기법별 패턴 컴파일
      config['techniques']&.each do |technique, tech_config|
        compiled_technique = compile_technique_patterns(tech_config)
        @compiled_patterns[attack_type]['techniques'][technique] = compiled_technique
      end
    end
    
    # 화이트리스트 컴파일
    compile_whitelist
    
    puts "[INFO] Compiled #{@compiled_patterns.keys.size} attack types"
  end
  
  def compile_technique_patterns(tech_config)
    return {} unless tech_config&.dig('patterns')
    
    case_sensitive = @pattern_config.dig('global_config', 'case_sensitive') || false
    flags = case_sensitive ? 0 : Regexp::IGNORECASE
    
    compiled_patterns = tech_config['patterns'].map do |pattern|
      begin
        Regexp.new(pattern, flags)
      rescue RegexpError => e
        puts "[WARN] Invalid pattern skipped: #{pattern} (#{e.message})"
        nil
      end
    end.compact
    
    {
      'patterns' => compiled_patterns,
      'description' => tech_config['description'] || 'No description',
      'pattern_count' => compiled_patterns.size
    }
  end
  
  def compile_whitelist
    @whitelist_ips = []
    
    # IP 화이트리스트 컴파일
    ip_ranges = @pattern_config.dig('whitelist', 'ip_ranges') || []
    ip_ranges.each do |range|
      begin
      # 환경변수 처리 추가
        expanded_range = range.gsub(/\$\{([^}]+)\}/) { |match| 
            var_with_default = $1
            if var_with_default.include?(':-')
            var_name, default_value = var_with_default.split(':-', 2)
            ENV[var_name] || default_value
            else
            ENV[var_with_default] || match
            end
        }

        @whitelist_ips << IPAddr.new(expanded_range)
      rescue IPAddr::InvalidAddressError => e
        puts "[WARN] Invalid IP range skipped: #{range} (#{e.message})"
      end
    end
    
    puts "[INFO] Whitelist compiled: #{@whitelist_ips.size} IP ranges"
  end
  
  #---------------------------------------------------------------------------
  # 🎯 메인 탐지 엔진
  #---------------------------------------------------------------------------
  
  def detect_attacks(message, source_ip = nil)
    # 30초마다만 설정 파일 변경 확인
    check_configurations if Time.now - @last_config_check > CONFIG_CHECK_INTERVAL
    
    # 입력 검증
    return [] if message.nil? || message.strip.empty?
    
    # 화이트리스트 체크
    return [] if whitelisted?(source_ip)
    
    detected_attacks = []
    max_detections = @pattern_config.dig('global_config', 'max_patterns_per_message') || 10
    
    # 각 공격 타입별 패턴 매칭
    @compiled_patterns.each do |attack_type, attack_config|
      attack_config['techniques'].each do |technique, tech_config|
        
        # 해당 기법의 패턴들 중 하나라도 매칭되면 공격 탐지
        matched_pattern = find_matching_pattern(message, tech_config['patterns'])
        
        if matched_pattern
          attack_info = {
            'category' => attack_type,
            'technique' => technique,
            'severity' => attack_config['severity'],
            'description' => tech_config['description'],
            'matched_pattern' => matched_pattern.source,
            'confidence' => calculate_confidence(matched_pattern, message)
          }
          
          detected_attacks << attack_info
          
          # 최대 탐지 개수 제한
          break if detected_attacks.size >= max_detections
        end
      end
      
      # 최대 탐지 개수 제한  
      break if detected_attacks.size >= max_detections
    end
    
    # 심각도 순으로 정렬 (가장 심각한 것부터)
    sort_by_severity(detected_attacks)
  end
  
  #---------------------------------------------------------------------------
  # 보조 메서드들
  #---------------------------------------------------------------------------
  
  def find_matching_pattern(message, patterns)
    patterns.each do |pattern|
      return pattern if message.match?(pattern)
    end
    nil
  end
  
  def calculate_confidence(pattern, message)
    # 상수를 사용한 신뢰도 계산
    base_confidence = DEFAULT_BASE_CONFIDENCE
    
    # 패턴이 복잡할수록 높은 신뢰도
    pattern_complexity = pattern.source.length / PATTERN_LENGTH_DIVISOR
    complexity_bonus = [pattern_complexity * COMPLEXITY_MULTIPLIER, MAX_COMPLEXITY_BONUS].min
    
    # 메시지에서 의심스러운 문자가 많을수록 높은 신뢰도
    suspicious_chars = message.scan(/['"<>;|&$`{}()\\]/).size
    suspicious_bonus = [suspicious_chars * SUSPICIOUS_CHAR_MULTIPLIER, MAX_SUSPICIOUS_BONUS].min
    
    confidence = base_confidence + complexity_bonus + suspicious_bonus
    [confidence, 1.0].min.round(2)
  end
  
  def whitelisted?(source_ip)
    return false unless source_ip && source_ip != '-'
    
    begin
      ip_addr = IPAddr.new(source_ip)
      @whitelist_ips.any? { |range| range.include?(ip_addr) }
    rescue IPAddr::InvalidAddressError
      false
    end
  end
  
  def sort_by_severity(attacks)
    severity_scores = @severity_config['severity_levels'] || {}
    
    attacks.sort_by do |attack|
      -(severity_scores[attack['severity']] || 0)  # 내림차순 정렬
    end
  end
  
  #---------------------------------------------------------------------------
  # 통계 및 디버깅 메서드
  #---------------------------------------------------------------------------
  
  def get_stats
    {
      'loaded_patterns' => @compiled_patterns.keys.size,
      'total_techniques' => @compiled_patterns.values.sum { |v| v['techniques'].size },
      'whitelist_ips' => @whitelist_ips.size,
      'pattern_file_mtime' => @last_pattern_modified,
      'severity_file_mtime' => @last_severity_modified,
      'last_config_check' => @last_config_check
    }
  end
  
  def list_available_attacks
    @compiled_patterns.map do |attack_type, config|
      {
        'type' => attack_type,
        'severity' => config['severity'],
        'techniques' => config['techniques'].keys,
        'total_patterns' => config['techniques'].values.sum { |t| t['pattern_count'] }
      }
    end
  end
  
  #---------------------------------------------------------------------------
  # 기본 설정 (fallback)
  #---------------------------------------------------------------------------
  
  private
  
  def default_pattern_config
    {
      'metadata' => { 'version' => 'fallback-1.0' },
      'global_config' => { 'case_sensitive' => false, 'max_patterns_per_message' => 10 },
      'attack_patterns' => {
        'SQL_INJECTION' => {
          'enabled' => true,
          'description' => 'Basic SQL injection detection',
          'techniques' => {
            'basic' => {
              'patterns' => ['union\\s+select', 'sleep\\s*\\(', "'\\s*or\\s*'"],
              'description' => 'Basic SQL injection patterns'
            }
          }
        }
      },
      'whitelist' => { 'ip_ranges' => ['127.0.0.1/32'] }
    }
  end
  
  def default_severity_config
    {
      'metadata' => { 'version' => 'fallback-1.0' },
      'attack_severity' => { 'SQL_INJECTION' => 'high' },
      'severity_levels' => { 'info' => 1, 'low' => 2, 'medium' => 3, 'high' => 4, 'critical' => 5 }
    }
  end
end