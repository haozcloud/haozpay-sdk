package haozpay

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"

	"github.com/go-resty/resty/v2"
)

// signatureMiddleware 请求签名中间件
// 在每个请求发送前自动添加签名字段
//
// 皓臻支付签名算法:
//   1. 收集请求参数(排除sign字段)
//   2. 按参数名ASCII码升序排序
//   3. 按"key=value"格式用&拼接成字符串
//   4. 用SHA256算法生成摘要
//   5. 用商户私钥对摘要进行RSA加密
//
// 参数:
//   - privateKeyPEM: 商户私钥(PEM格式)
//
// 返回:
//   - resty.RequestMiddleware: resty 请求中间件函数
func signatureMiddleware(privateKeyPEM string) resty.RequestMiddleware {
	return func(c *resty.Client, r *resty.Request) error {
		if r.Body == nil {
			return nil
		}

		haozReq, ok := r.Body.(*HaozPayRequest)
		if !ok {
			return nil
		}

		paramsMap := make(map[string]string)
		paramsMap["merchantNo"] = haozReq.MerchantNo
		paramsMap["timestamp"] = fmt.Sprintf("%d", haozReq.Timestamp)
		if haozReq.BizBody != "" {
			paramsMap["bizBody"] = haozReq.BizBody
		}

		sign, err := generateHaozPaySignature(privateKeyPEM, paramsMap)
		if err != nil {
			return fmt.Errorf("failed to generate signature: %w", err)
		}

		haozReq.Sign = sign
		r.SetBody(haozReq)

		return nil
	}
}

// generateHaozPaySignature 生成皓臻支付请求签名
// 使用 SHA256WithRSA 算法对参数进行签名
//
// 参数:
//   - privateKeyPEM: 商户私钥(PEM格式)
//   - params: 请求参数(不含sign字段)
//
// 返回:
//   - string: Base64编码的签名字符串
//   - error: 签名失败时返回错误
func generateHaozPaySignature(privateKeyPEM string, params map[string]string) (string, error) {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for i, key := range keys {
		value := params[key]
		if value != "" {
			if i > 0 {
				sb.WriteString("&")
			}
			sb.WriteString(key)
			sb.WriteString("=")
			sb.WriteString(value)
		}
	}

	paramsStr := sb.String()

	hash := sha256.Sum256([]byte(paramsStr))

	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// parsePrivateKey 解析PEM格式的私钥
func parsePrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}

	return rsaKey, nil
}

// verifyHaozPaySignature 验证皓臻支付回调签名
// 使用平台公钥验证签名
//
// 参数:
//   - publicKeyPEM: 平台公钥(PEM格式)
//   - params: 回调参数(不含sign字段)
//   - signature: Base64编码的签名字符串
//
// 返回:
//   - error: 验签失败时返回错误
func verifyHaozPaySignature(publicKeyPEM string, params map[string]string, signature string) error {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for i, key := range keys {
		value := params[key]
		if value != "" {
			if i > 0 {
				sb.WriteString("&")
			}
			sb.WriteString(key)
			sb.WriteString("=")
			sb.WriteString(value)
		}
	}

	paramsStr := sb.String()
	hash := sha256.Sum256([]byte(paramsStr))

	publicKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], sigBytes)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// parsePublicKey 解析PEM格式的公钥
func parsePublicKey(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return pubKey, nil
}

// errorHandlerMiddleware 错误处理中间件
// 在接收到响应后检查 HTTP 状态码，如果是错误状态则解析错误信息
//
// 处理逻辑:
//   1. 检查 HTTP 状态码是否 >= 400
//   2. 如果是错误状态，尝试解析响应体中的错误信息
//   3. 将错误信息包装为 SDKError 类型返回
//
// 返回:
//   - resty.ResponseMiddleware: resty 响应中间件函数
func errorHandlerMiddleware() resty.ResponseMiddleware {
	return func(c *resty.Client, r *resty.Response) error {
		// 检查是否为错误状态码
		if r.StatusCode() >= 400 {
			var errResp Response
			
			// 尝试解析错误响应
			if err := json.Unmarshal(r.Body(), &errResp); err != nil {
				// 解析失败时返回通用错误
				return NewSDKError(
					0,
					"failed to parse error response",
					r.StatusCode(),
				)
			}
			
			// 返回包含详细信息的 SDK 错误
			return NewSDKErrorWithRequestID(
				errResp.Code,
				errResp.Message,
				r.StatusCode(),
				errResp.RequestID,
			)
		}
		return nil
	}
}

// requestLogMiddleware 请求日志中间件
// 在调试模式下打印请求详情
//
// 打印内容:
//   - 请求方法和 URL
//   - 请求体内容(格式化的 JSON)
//
// 参数:
//   - debug: 是否开启调试模式
//
// 返回:
//   - resty.RequestMiddleware: resty 请求中间件函数
func requestLogMiddleware(debug bool) resty.RequestMiddleware {
	return func(c *resty.Client, r *resty.Request) error {
		if debug {
			// 打印请求行
			fmt.Printf("[SDK Request] %s %s\n", r.Method, r.URL)
			
			// 打印请求体
			if r.Body != nil {
				bodyBytes, _ := json.MarshalIndent(r.Body, "", "  ")
				fmt.Printf("[SDK Request Body] %s\n", string(bodyBytes))
			}
		}
		return nil
	}
}

// responseLogMiddleware 响应日志中间件
// 在调试模式下打印响应详情
//
// 打印内容:
//   - HTTP 状态码
//   - 请求耗时
//   - 响应体内容
//
// 参数:
//   - debug: 是否开启调试模式
//
// 返回:
//   - resty.ResponseMiddleware: resty 响应中间件函数
func responseLogMiddleware(debug bool) resty.ResponseMiddleware {
	return func(c *resty.Client, r *resty.Response) error {
		if debug {
			// 打印响应状态和耗时
			fmt.Printf("[SDK Response] Status: %d, Time: %v\n", 
				r.StatusCode(), r.Time())
			
			// 打印响应体
			fmt.Printf("[SDK Response Body] %s\n", string(r.Body()))
		}
		return nil
	}
}