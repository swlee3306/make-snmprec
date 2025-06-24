package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
)

var (
	oidCache = make(map[string]string)
)

var typeMap = map[gosnmp.Asn1BER]int{
	gosnmp.OctetString:      4,
	gosnmp.ObjectIdentifier: 6,
	gosnmp.Integer:          2,
	gosnmp.Counter32:        65,
	gosnmp.Gauge32:          66,
	gosnmp.TimeTicks:        67,
	gosnmp.Counter64:        70,
	gosnmp.IPAddress:        64,
}

// func safeString(pdu gosnmp.SnmpPDU) string {
// 	values := extractValues([]gosnmp.SnmpPDU{pdu})
// 	if len(values) == 0 {
// 		return ""
// 	}
// 	switch v := values[0].(type) {
// 	case string:
// 		return v
// 	case []byte:
// 		if utf8.Valid(v) {
// 			return string(v)
// 		}
// 		return fmt.Sprintf("0x%x", v)
// 	default:
// 		return fmt.Sprintf("%v", v)
// 	}
// }

// // SNMP Walk 결과에서 값 추출
// func extractValues(pdus []gosnmp.SnmpPDU) []interface{} {
// 	var values []interface{}
// 	for _, pdu := range pdus {
// 		switch pdu.Type {
// 		case gosnmp.OctetString:
// 			values = append(values, string(pdu.Value.([]byte)))
// 		default:
// 			values = append(values, pdu.Value)
// 		}
// 	}
// 	return values
// }

func main() {
	if len(os.Args) < 3 {
		fmt.Println("사용법: snmprec-data-get <target_ip> <community> <snmprecname> or snmprec-data-get <target_ip> <community>")
		os.Exit(1)
	}

	target := os.Args[1]
	community := os.Args[2]

	var outputFile string
	var snmprecname string

	if len(os.Args) >= 4 {
		snmprecname = os.Args[3]
	} else {
		snmprecname = ""
	}

	if snmprecname != "" {
		outputFile = snmprecname + ".snmprec"
	} else {
		outputFile = community + ".snmprec"
	}

	snmp := &gosnmp.GoSNMP{
		Target:         target,
		Community:      community,
		Port:           161,
		Version:        gosnmp.Version2c,
		Timeout:        5 * time.Second,
		Retries:        3,
		MaxRepetitions: 50,
		MaxOids:        100,
	}
	err := snmp.Connect()
	if err != nil {
		fmt.Fprintf(os.Stderr, "SNMP 연결 실패: %v\n", err)
		os.Exit(1)
	}
	defer snmp.Conn.Close()

	allResults := []gosnmp.SnmpPDU{}

	// 여러 루트 OID 구간을 명시적으로 지정해서 모든 영역 커버
	baseOIDs := []string{
		".1.0",       // LLDP 등 특수 루트
		".1.3.6",     // 표준 MIB
		".1.3.6.1.4", // Private Enterprise
	}

	for _, base := range baseOIDs {
		results, err := snmp.BulkWalkAll(base)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Walk 실패 (%s): %v\n", base, err)
			continue
		}
		allResults = append(allResults, results...)
	}

	out, err := os.Create(outputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "출력 파일 생성 실패: %v\n", err)
		os.Exit(1)
	}
	defer out.Close()

	for _, pdu := range allResults {
		oid := strings.TrimPrefix(pdu.Name, ".")
		var valueStr string

		if pdu.Value == nil {
			valueStr = ""
		} else {
			switch pdu.Type {
			case gosnmp.OctetString:
				data, ok := pdu.Value.([]byte)
				if !ok || len(data) == 0 {
					valueStr = ""
				} else {
					// Step 1: base64 encode and decode to simulate data cleaning
					encoded := base64.StdEncoding.EncodeToString(data)
					decoded, err := base64.StdEncoding.DecodeString(encoded)
					if err != nil {
						valueStr = fmt.Sprintf("0x%x", data)
					} else if utf8.Valid(decoded) {
						valueStr = escapeString(string(decoded))
					} else {
						valueStr = fmt.Sprintf("0x%x", decoded)
					}
				}
			case gosnmp.ObjectIdentifier:
				valueStr = fmt.Sprintf("%s", pdu.Value)
			case gosnmp.Integer, gosnmp.Counter32, gosnmp.Gauge32, gosnmp.TimeTicks, gosnmp.Uinteger32:
				valueStr = fmt.Sprintf("%d", pdu.Value)
			case gosnmp.Counter64:
				if val, ok := pdu.Value.(uint64); ok {
					valueStr = fmt.Sprintf("%d", val)
				} else {
					valueStr = fmt.Sprintf("%v", pdu.Value)
				}
			case gosnmp.IPAddress:
				valueStr = fmt.Sprintf("%s", pdu.Value)
			case gosnmp.OpaqueFloat:
				if val, ok := pdu.Value.(float32); ok {
					valueStr = fmt.Sprintf("%f", val)
				} else {
					valueStr = fmt.Sprintf("%v", pdu.Value)
				}
			case gosnmp.OpaqueDouble:
				if val, ok := pdu.Value.(float64); ok {
					valueStr = fmt.Sprintf("%f", val)
				} else {
					valueStr = fmt.Sprintf("%v", pdu.Value)
				}
			default:
				valueStr = fmt.Sprintf("%v", pdu.Value)
			}
		}

		typeCode := 0
		if code, ok := typeMap[pdu.Type]; ok {
			typeCode = code
		}

		valueStr = strings.ReplaceAll(valueStr, "\n", "")
		if _, err := out.WriteString(fmt.Sprintf("%s|%d|%s\n", oid, typeCode, valueStr)); err != nil {
			fmt.Fprintf(os.Stderr, "쓰기 실패 (%s): %v\n", oid, err)
		}
	}

	cacheFile, _ := os.Create("oid_cache.json")
	defer cacheFile.Close()
	if err := json.NewEncoder(cacheFile).Encode(oidCache); err != nil {
		fmt.Fprintf(os.Stderr, "OID 캐시 저장 실패: %v\n", err)
	}

	fmt.Printf("SNMP 데이터 수집 완료: %s\n", outputFile)
}

func escapeString(s string) string {
	var builder strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			builder.WriteString("\\\\")
		case '~':
			builder.WriteString("\\~")
		case '|':
			builder.WriteString("\\|")
		case '\n':
			builder.WriteString("\\n")
		case '\r':
			builder.WriteString("\\r")
		case '\t':
			builder.WriteString("\\t")
		default:
			if r < 32 || r == 127 {
				builder.WriteString(fmt.Sprintf("\\x%02x", r))
			} else {
				builder.WriteRune(r)
			}
		}
	}
	return builder.String()
}
