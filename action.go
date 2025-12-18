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
		return nil, fmt.Errorf("failed to list certs from Cloud: %w", err)
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
		snisPartial := relation == 1

		// 如果满足条件，将 id 加入 deleteCertKeyList（去重）：
		// 1) desc 相同但 snis 不完全一致（包括部分匹配或完全不同）
		// 2) snis 部分匹配且 desc 不相同
		if id != "" && ((desc == note && !snisMatch) || (snisPartial && desc != note)) {
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
		certKey, err = a.uploadCertToApisix(certStr, keyStr, note, domain)
		if err != nil || certKey == "" {
			return nil, fmt.Errorf("failed to upload to Cloud: %w", err)
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

func (a Auth) uploadCertToApisix(cert, key, note string, domain []string) (string, error) {
	params := map[string]any{
		"cert": cert,
		"key":  key,
		"desc": note,
		"snis": domain,
	}

	res, err := a.ApisixAPI("/ssls", params, "POST")
	if err != nil {
		return "", fmt.Errorf("failed to call Cloud API: %w", err)
	}
	code, ok := res["code"].(float64)
	if !ok {
		return "", fmt.Errorf("invalid response format: code not found")
	}
	if code != 200 {
		return "", fmt.Errorf("cloud API error: %s", res["msg"])
	}
	data, ok := res["data"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("invalid response format: data not found")
	}
	certKey, ok := data["key"].(string)
	if !ok {
		return "", fmt.Errorf("invalid response format: key not found")
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
		return nil, fmt.Errorf("failed to call Cloud API: %w", err)
	}
	list, ok := res["list"].(map[string]any)
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
	var result map[string]interface{}
	err = json.Unmarshal(r, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
