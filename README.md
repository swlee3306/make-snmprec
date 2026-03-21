# make-snmprec

## 한 줄 소개
SNMP 데이터를 수집해 `.snmprec` 시뮬레이션 파일로 변환하는 도구입니다.

## 저장소 성격
- 분류: 인프라 / 네트워크 도구
- 목적: SNMP 테스트와 시뮬레이션 환경 구성 지원
- 핵심 기술: Go, SNMP, 네트워크 장비 데이터 수집

SNMP 데이터 수집 및 시뮬레이션 파일 변환 도구

## 개요

`make-snmprec`는 SNMP 장비에서 데이터를 수집하여 `.snmprec` 형식의 시뮬레이션 파일로 변환하는 Go 프로그램입니다. 이 도구는 SNMP 모니터링 테스트나 시뮬레이션 환경 구축에 유용합니다.

## 주요 기능

- **SNMP 데이터 수집**: SNMP v2c를 통한 실시간 데이터 수집
- **다중 OID 지원**: 여러 루트 OID 구간을 커버하는 포괄적 데이터 수집
- **시뮬레이션 파일 생성**: 수집된 데이터를 `.snmprec` 형식으로 변환
- **데이터 타입 매핑**: SNMP 데이터 타입을 적절한 형식으로 변환
- **UTF-8 검증**: 텍스트 데이터의 유효성 검사 및 이스케이프 처리

## 아키텍처

### 지원하는 SNMP 데이터 타입
- **OctetString**: 문자열 데이터
- **ObjectIdentifier**: OID 데이터
- **Integer**: 정수 데이터
- **Counter32/64**: 카운터 데이터
- **Gauge32**: 게이지 데이터
- **TimeTicks**: 시간 데이터
- **IPAddress**: IP 주소 데이터

### 수집 범위
- **`.1.0`**: LLDP 등 특수 루트
- **`.1.3.6`**: 표준 MIB
- **`.1.3.6.1.4`**: Private Enterprise

## 사용법

### 기본 사용법
```bash
# 기본 수집 (community 이름으로 파일명 생성)
./snmprec-data-get <target_ip> <community>

# 사용자 지정 파일명으로 수집
./snmprec-data-get <target_ip> <community> <snmprecname>
```

### 예시
```bash
# 공개 SNMP로 수집
./snmprec-data-get 192.168.1.1 public

# 사용자 지정 파일명으로 수집
./snmprec-data-get 192.168.1.1 public mydevice
```

## 출력 파일 형식

생성되는 `.snmprec` 파일은 다음과 같은 형식을 따릅니다:
```
1.3.6.1.2.1.1.1.0|4|Linux server 5.4.0-42-generic
1.3.6.1.2.1.1.3.0|67|123456
```

각 라인은 다음 형식입니다:
- **OID**: SNMP 객체 식별자
- **타입 코드**: SNMP 데이터 타입 코드
- **값**: 실제 데이터 값

## 설정 옵션

### SNMP 연결 설정
- **타임아웃**: 5초
- **재시도 횟수**: 3회
- **최대 반복**: 50회
- **최대 OID**: 100개

### 데이터 처리
- **Base64 인코딩/디코딩**: 데이터 정제를 위한 이중 처리
- **UTF-8 검증**: 텍스트 데이터 유효성 검사
- **이스케이프 처리**: 특수 문자 처리

## 파일 구조

```
make-snmprec/
├── main.go              # 메인 프로그램
├── go.mod              # Go 모듈 정의
├── go.sum              # 의존성 체크섬
├── command.txt         # 명령어 참조
├── sampleFile/         # 샘플 파일
│   ├── okestro.snmprec
│   └── public.snmprec
└── snmprec-data-get    # 컴파일된 실행 파일
```

## 의존성

- **Go 1.16+**
- **github.com/gosnmp/gosnmp**: SNMP 통신 라이브러리

## 빌드 및 실행

### 빌드
```bash
go build -o snmprec-data-get main.go
```

### 실행
```bash
./snmprec-data-get 192.168.1.1 public
```

## 사용 사례

- **모니터링 테스트**: SNMP 모니터링 시스템 테스트
- **시뮬레이션 환경**: 실제 장비 없이 SNMP 데이터 시뮬레이션
- **데이터 백업**: SNMP 장비의 현재 상태 백업
- **개발 테스트**: SNMP 관련 애플리케이션 개발 시 테스트 데이터 생성

## 주의사항

- **네트워크 접근**: 대상 장비에 SNMP 접근 권한 필요
- **방화벽 설정**: SNMP 포트(161) 접근 허용 필요
- **데이터 크기**: 대용량 데이터 수집 시 시간이 오래 걸릴 수 있음
- **권한**: SNMP 읽기 권한이 있는 community 문자열 필요

## 라이선스

MIT License

## 개발자 정보

- **언어**: Go
- **목적**: SNMP 데이터 수집 및 시뮬레이션
- **대상**: 네트워크 모니터링 및 테스트 환경
