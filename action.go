package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
)

type Auth struct {
	AdminKey      string `json:"admin_key"`
	ServerAddress string `json:"server_address"`
}

func NewAuth(adminKey, serverAddress string) *Auth {
	return &Auth{
		AdminKey:      adminKey,
		ServerAddress: serverAddress,
	}
}

func Upload_bind(cfg map[string]any) (*Response, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	certStr, ok := cfg["cert"].(string)
	if !ok || certStr == "" {
		return nil, fmt.Errorf("cert is required and must be a string")
	}
	keyStr, ok := cfg["key"].(string)
	if !ok || keyStr == "" {
		return nil, fmt.Errorf("key is required and must be a string")
	}
	adminKey, ok := cfg["admin_key"].(string)
	if !ok || adminKey == "" {
		return nil, fmt.Errorf("admin_key is required and must be a string")
	}
	serverAddress, ok := cfg["server_address"].(string)
	if !ok || serverAddress == "" {
		return nil, fmt.Errorf("server_address is required and must be a string")
	}
	domains, ok := cfg["domain"].([]interface{})
	if !ok || len(domains) == 0 {
		return nil, fmt.Errorf("domain is required and must be a []interface{}")
	}
	domain := make([]string, len(domains))
	for i, v := range domains {
		if str, ok := v.(string); ok {
			domain[i] = str
		} else {
			// 如果断言失败，可以处理错误
			return nil, fmt.Errorf("element at index %d is not a string", i)
		}
	}
	extra, err := parseExtraParams(cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid extra params: %w", err)
	}
	sha256, err := GetSHA256(certStr)
	if err != nil {
		return nil, fmt.Errorf("failed to get SHA256 of cert: %w", err)
	}
	note := fmt.Sprintf("allinssl-%s", sha256)

	a := NewAuth(adminKey, serverAddress)
	// 检查证书是否已存在于服务器
	// 只根据证书名称检查是否存在，格式为 "allinssl-<sha256>"
	certServer, err := a.listCertFromApisix()
	if err != nil {
		return nil, fmt.Errorf("failed to list certs from Apisix: %w", err)
	}
	// certKey 为空表示未找到匹配的证书
	var deleteCertKeyList []string = []string{}
	deleteMap := make(map[string]bool)
	var certKey string = ""
	for _, cert := range certServer {
		value, ok := cert["value"].(map[string]any)
		if !ok {
			continue
		}
		desc, _ := value["desc"].(string)
		// 尝试取证书 id（可能在 value 中）
		var id string
		if v, ok := value["id"].(string); ok {
			id = v
		}
		// 尝试解析 snis
		snisAny, _ := value["snis"].([]any)
		snis := make([]string, 0)
		valid := true
		if snisAny != nil {
			for _, v := range snisAny {
				s, ok := v.(string)
				if !ok {
					valid = false
					break
				}
				snis = append(snis, s)
			}
		} else {
			valid = false
		}

		// relation: 0=none,1=partial,2=exact
		relation := 0
		if valid {
			relation = compareSliceRelation(snis, domain)
		}
		snisMatch := relation == 2
		snisPartial := relation == 0

		// 如果满足条件，将 id 加入 deleteCertKeyList（去重）：
		// 1) desc 相同但 snis 不完全一致（包括部分匹配或完全不同）
		// 2) snis 部分匹配且 desc 不相同
		if id != "" && ((desc == note && !snisMatch) || (!snisPartial && desc != note)) {
			if !deleteMap[id] {
				deleteCertKeyList = append(deleteCertKeyList, id)
				deleteMap[id] = true
			}
		}

		// 优先返回同时满足 desc==note 且 snis 匹配的证书
		if snisMatch && desc == note {
			certKey = id
			// 继续寻找更优匹配
			continue
		}
	}
	// 如果证书不存在，则上传证书
	if certKey == "" {
		certKey, err = a.uploadCertToApisix(certStr, keyStr, note, domain, extra)
		if err != nil || certKey == "" {
			return nil, fmt.Errorf("failed to upload to Apisix: %w", err)
		}
		if len(deleteCertKeyList) > 0 {
			// 删除多余的证书绑定
			for _, delCertKey := range deleteCertKeyList {
				_, err := a.DeleteCertFromApisix(delCertKey)
				if err != nil {
					// 记录错误但继续删除其他证书
					fmt.Printf("Warning: failed to delete cert %s: %v\n", delCertKey, err)
					_, err := a.DeleteCertFromApisix(certKey)
					if err != nil {
						fmt.Printf("Warning: failed to rollback cert %s: %v\n", certKey, err)
					}
					return nil, fmt.Errorf("failed to delete old cert %s: %w", delCertKey, err)
				}
			}
		}
		return &Response{
			Status:  "success",
			Message: "Certificate uploaded and bound successfully",
			Result:  map[string]interface{}{"message": "绑定成功"},
		}, nil
	} else {
		// 证书已存在，跳过上传步骤
		return &Response{
			Status:  "success",
			Message: "Certificate uploaded and bound successfully",
			Result:  map[string]interface{}{"message": "已存在绑定"},
		}, nil
	}
}

func (a Auth) uploadCertToApisix(cert, key, note string, domain []string, extra map[string]any) (string, error) {
	params := map[string]any{
		"cert": cert,
		"key":  key,
		"desc": note,
		"snis": domain,
	}
	// 合并额外参数（cert/key/snis/desc 已在 parseExtraParams 中保护，不会被覆盖）
	for k, v := range extra {
		params[k] = v
	}

	res, err := a.ApisixAPI("/ssls", params, "POST")
	if err != nil {
		return "", fmt.Errorf("failed to call Apisix API: %w", err)
	}
	certKey, ok := res["key"].(string)
	if !ok {
		return "", fmt.Errorf("invalid response format: data not found")
	}
	return certKey, nil
}

func (a Auth) DeleteCertFromApisix(certKey string) (bool, error) {
	res, err := a.ApisixAPI("/ssls/"+certKey, map[string]interface{}{}, "DELETE")
	if err != nil {
		return false, fmt.Errorf("failed to call Apisix API: %w", err)
	}
	_, ok := res["deleted"].(string)
	if !ok {
		return false, fmt.Errorf("apisix api error: %s", res["message"])
	}
	key, ok := res["key"].(string)
	if !ok {
		return false, fmt.Errorf("invalid response format: key not found")
	}
	reqKey := path.Base(key)
	if reqKey != certKey {
		return false, fmt.Errorf("deleted key mismatch: expected %s, got %s", certKey, key)
	}
	return true, nil

}

func (a Auth) listCertFromApisix() ([]map[string]any, error) {
	res, err := a.ApisixAPI("/ssls", map[string]interface{}{}, "GET")
	if err != nil {
		return nil, fmt.Errorf("failed to call Apisix API: %w", err)
	}
	list, ok := res["list"].([]any)
	if !ok {
		return nil, fmt.Errorf("invalid response format: data not found")
	}
	certs := make([]map[string]any, 0, len(list))
	for _, cert := range list {
		certMap, ok := cert.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid response format: cert item is not a map")
		}
		certs = append(certs, certMap)
	}
	return certs, nil
}

// 比较两个字符串切片是否包含相同元素（顺序不敏感）
// compareSliceRelation compares two string slices and returns:
// 0 => no overlap, 1 => partial overlap (some common elements, but not identical), 2 => exactly identical (same elements and counts)
func compareSliceRelation(a, b []string) int {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	// count elements of a
	cnt := make(map[string]int)
	for _, s := range a {
		cnt[s]++
	}
	overlap := 0
	// track counts for exact comparison
	cntCopy := make(map[string]int)
	for k, v := range cnt {
		cntCopy[k] = v
	}
	for _, s := range b {
		if cnt[s] > 0 {
			overlap++
			cnt[s]--
		}
	}
	// check exact: lengths equal and all counts in cnt are zero after matching
	exact := false
	if len(a) == len(b) {
		allZero := true
		for _, v := range cnt {
			if v != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			exact = true
		}
	}
	if exact {
		return 2
	}
	if overlap > 0 {
		return 1
	}
	// no overlap
	return 0
}

// ApisixAPI 支持 GET/DELETE/POST/PUT，所有非 GET/DELETE 请求使用 JSON；不再计算或发送签名。
// 约定：GET/DELETE 不包含参数；其他方法通过 JSON body 发送 `data`。
func (a Auth) ApisixAPI(apiPath string, data map[string]interface{}, method string) (map[string]interface{}, error) {
	AdminKey := a.AdminKey
	// 根据 method 构造请求（调用方必须传入有效 method）
	method = strings.ToUpper(method)
	var req *http.Request
	var err error
	urlStr := a.ServerAddress + apiPath
	if method == "GET" || method == "DELETE" {
		// GET/DELETE 不带参数，直接请求路径
		req, err = http.NewRequest(method, urlStr, nil)
		if err != nil {
			return nil, err
		}
	} else {
		_body, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		req, err = http.NewRequest(method, urlStr, strings.NewReader(string(_body)))
		if err != nil {
			return nil, err
		}
		req.Header.Add("Content-Type", "application/json")
	}

	// 公共请求头（不包含签名）
	req.Header.Add("X-API-KEY", AdminKey)

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyPreview := string(r)
		if len(bodyPreview) > 500 {
			bodyPreview = bodyPreview[:500] + "..."
		}
		return nil, fmt.Errorf("apisix returned HTTP %d: %s", resp.StatusCode, bodyPreview)
	}
	var result map[string]interface{}
	err = json.Unmarshal(r, &result)
	if err != nil {
		bodyPreview := string(r)
		if len(bodyPreview) > 500 {
			bodyPreview = bodyPreview[:500] + "..."
		}
		return nil, fmt.Errorf("apisix response is not valid JSON: %w, response: %s", err, bodyPreview)
	}
	return result, nil
}

// protectedSSLKeys 由插件管理，不允许通过 extra 参数覆盖
var protectedSSLKeys = map[string]bool{
	"cert": true,
	"key":  true,
	"snis": true,
	"desc": true,
}

// parseExtraParams 解析可选的额外参数：
//   - extra: JSON 字符串或 map，字段原样合并进 ssls 请求体（cert/key/snis/desc 不可覆盖），
//     例如 {"type":"server","status":1,"ssl_protocols":["TLSv1.2","TLSv1.3"],"labels":{"env":"production"}}
//   - ocsp_stapling: JSON 字符串或 map，OCSP Stapling 插件参数
func parseExtraParams(cfg map[string]any) (map[string]any, error) {
	extra := map[string]any{}

	if v, ok := cfg["extra"]; ok && v != nil {
		m, err := toStringMap(v, "extra")
		if err != nil {
			return nil, err
		}
		for k, val := range m {
			if protectedSSLKeys[k] {
				return nil, fmt.Errorf("extra cannot override protected field %q", k)
			}
			extra[k] = val
		}
	}

	if v, ok := cfg["ocsp_stapling"]; ok && v != nil {
		ocsp, err := parseOCSPStapling(v)
		if err != nil {
			return nil, err
		}
		if len(ocsp) > 0 {
			extra["ocsp_stapling"] = ocsp
		}
	}

	return extra, nil
}

// parseOCSPStapling 校验并规范化 ocsp_stapling 插件参数：
// enabled / skip_verify 为布尔值，cache_ttl 为 >= 60 的整数
func parseOCSPStapling(v any) (map[string]any, error) {
	m, err := toStringMap(v, "ocsp_stapling")
	if err != nil || m == nil {
		return nil, err
	}
	out := map[string]any{}
	if raw, ok := m["enabled"]; ok {
		b, err := toBool(raw, "ocsp_stapling.enabled")
		if err != nil {
			return nil, err
		}
		out["enabled"] = b
	}
	if raw, ok := m["skip_verify"]; ok {
		b, err := toBool(raw, "ocsp_stapling.skip_verify")
		if err != nil {
			return nil, err
		}
		out["skip_verify"] = b
	}
	if raw, ok := m["cache_ttl"]; ok {
		n, err := toInt64(raw, "ocsp_stapling.cache_ttl")
		if err != nil {
			return nil, err
		}
		if n < 60 {
			return nil, fmt.Errorf("ocsp_stapling.cache_ttl must be >= 60, got %d", n)
		}
		out["cache_ttl"] = n
	}
	return out, nil
}

// toStringMap 接受 map 或 JSON 对象字符串，统一转换为 map
func toStringMap(v any, field string) (map[string]any, error) {
	switch m := v.(type) {
	case map[string]any:
		return m, nil
	case string:
		if strings.TrimSpace(m) == "" {
			return nil, nil
		}
		var out map[string]any
		if err := json.Unmarshal([]byte(m), &out); err != nil {
			return nil, fmt.Errorf("%s must be a JSON object: %w", field, err)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s must be a JSON object string or map, got %T", field, v)
	}
}

func toBool(v any, field string) (bool, error) {
	switch b := v.(type) {
	case bool:
		return b, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(b)) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, fmt.Errorf("%s must be a boolean, got %v", field, v)
}

func toInt64(v any, field string) (int64, error) {
	switch n := v.(type) {
	case float64:
		if n != float64(int64(n)) {
			return 0, fmt.Errorf("%s must be an integer, got %v", field, v)
		}
		return int64(n), nil
	case json.Number:
		return n.Int64()
	case string:
		parsed, err := json.Number(strings.TrimSpace(n)).Int64()
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer: %w", field, err)
		}
		return parsed, nil
	}
	return 0, fmt.Errorf("%s must be an integer, got %v", field, v)
}
