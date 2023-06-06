<?php
/**
 * @link http://github.com/seffeng/
 * @copyright Copyright (c) 2021 seffeng
 */
namespace Seffeng\Afs;

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\RequestException;
use Seffeng\Afs\Exceptions\AfsException;
use Seffeng\Afs\Helpers\ArrayHelper;

class AfsClient
{
    /**
     *
     * @var string
     */
    const METHOD_GET = 'GET';

    /**
     *
     * @var string
     */
    private $scheme = 'https://';

    /**
     *
     * @var string
     */
    private $host = 'afs.aliyuncs.com';

    /**
     *
     * @var string
     */
    private $regionId = 'cn-hangzhou';

    /**
     *
     * @var string
     */
    private $action = 'AuthenticateSig';

    /**
     *
     * @var string
     */
    private $accessKeyId;

    /**
     *
     * @var string
     */
    private $accessSecret;

    /**
     *
     * @var string
     */
    private $format ='json';

    /**
     *
     * @var string
     */
    private $version = '2018-01-12';

    /**
     *
     * @var string
     */
    private $signature;

    /**
     *
     * @var string
     */
    private $signatureMethod = 'HMAC-SHA1';

    /**
     *
     * @var string
     */
    private $signatureNonce;

    /**
     *
     * @var string
     */
    private $signatureVersion = '1.0';

    /**
     *
     * @var string
     */
    private $timestamp;

    /**
     *
     * @var string
     */
    private $token;

    /**
     *
     * @var string
     */
    private $sig;

    /**
     *
     * @var string
     */
    private $sessionId;

    /**
     *
     * @var string
     */
    private $scene;

    /**
     *
     * @var string
     */
    private $appKey;

    /**
     *
     * @var string
     */
    private $remoteIp;

    /**
     *
     * @var boolean
     */
    private $debug;

    /**
     *
     * @var integer
     */
    private $timeout = 30;

    /**
     *
     * @var HttpClient
     */
    private $httpClient;

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @param string $accessKeyId
     * @param string $accessSecret
     * @param string $appKey
     * @return static
     */
    public function __construct(string $accessKeyId, string $accessSecret, string $appKey)
    {
        $this->setAccessKeyId($accessKeyId)->setAccessSecret($accessSecret)->setAppKey($appKey);
        $this->httpClient = new HttpClient(['base_uri' => $this->getscheme() . $this->getHost(), 'timeout' => $this->getTimeout()]);
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @throws AfsException
     * @throws \Exception
     * @return boolean
     */
    public function verify()
    {
        try {
            if ($this->getDebug()) {
                return true;
            }
            $params = $this->getParams();
            $headers = $this->getHeaders();
            $query = array_merge($headers, $params);
            $this->setSignature($query);
            $query['Signature'] = $this->getSignature();

            $request = $this->httpClient->get('/', [
                'query' => $query
            ]);
            $message = '验证失败！';
            if ($request->getStatusCode() === 200) {
                $body = $request->getBody()->getContents();
                $body = json_decode($body, true);
                $errorCode = ArrayHelper::getValue($body, 'Code');

                if ($errorCode && $errorCode === 100) {
                    return true;
                } else {
                    $message = ArrayHelper::getValue($body, 'Msg', '');
                }
            }
            throw new AfsException($message);
        } catch (RequestException $e) {
            $message = $e->getResponse()->getBody()->getContents();
            if (!$message) {
                $message = $e->getMessage();
            }
            throw new AfsException($message);
        } catch (\Exception $e) {
            throw $e;
        }
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return array
     */
    public function getHeaders()
    {
        return [
            'AccessKeyId' => $this->getAccessKeyId(),
            'Action' => $this->getAction(),
            'SignatureMethod' => $this->getSignatureMethod(),
            'SignatureNonce' => $this->getSignatureNonce(),
            'SignatureVersion' => $this->getSignatureVersion(),
            'Timestamp' => $this->getDateTime(),
            'Version' => $this->getVersion(),
            'Format' => $this->getFormat(),
        ];
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @param  string|array $phone
     * @param  array $content
     * @return array
     */
    public function getParams()
    {
        return [
            'Token' => $this->getToken(),
            'Sig' => $this->getSig(),
            'SessionId' => $this->getSessionId(),
            'Scene' => $this->getScene(),
            'AppKey' => $this->getAppKey(),
            'RemoteIp' => $this->getRemoteIp(),
        ];
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @param string $token
     * @return static
     */
    public function setRemoteIp(string $remoteIp)
    {
        $this->remoteIp = $remoteIp;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return string
     */
    public function getRemoteIp()
    {
        return $this->remoteIp;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @param string $token
     * @return static
     */
    public function setAppKey(string $appKey)
    {
        $this->appKey = $appKey;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return string
     */
    public function getAppKey()
    {
        return $this->appKey;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @param string $token
     * @return static
     */
    public function setScene(string $scene)
    {
        $this->scene = $scene;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return string
     */
    public function getScene()
    {
        return $this->scene;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @param string $token
     * @return static
     */
    public function setSessionId(string $sessionId)
    {
        $this->sessionId = $sessionId;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return string
     */
    public function getSessionId()
    {
        return $this->sessionId;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @param string $token
     * @return static
     */
    public function setToken(string $token)
    {
        $this->token = $token;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return string
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @param string $token
     * @return static
     */
    public function setSig(string $sig)
    {
        $this->sig = $sig;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return string
     */
    public function getSig()
    {
        return $this->sig;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return boolean
     */
    public function getIsHttps()
    {
        return isset($_SERVER['HTTPS']) ? ((empty($_SERVER['HTTPS']) || strtolower($_SERVER['HTTPS']) === 'off') ? false : true) : false;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return string
     */
    public function getscheme()
    {
        return $this->getIsHttps() ? 'https://' : 'http://';
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return string
     */
    public function getHost()
    {
        return $this->host;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @param  string $accessKeyId
     * @return static
     */
    public function setAccessKeyId(string $accessKeyId)
    {
        $this->accessKeyId = $accessKeyId;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return string
     */
    public function getAccessKeyId()
    {
        return $this->accessKeyId;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @param  string $accessSecret
     * @return static
     */
    public function setAccessSecret(string $accessSecret)
    {
        $this->accessSecret = $accessSecret;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return string
     */
    public function getAccessSecret()
    {
        return $this->accessSecret;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @param integer $timeout
     * @return static
     */
    public function setTimeout(int $timeout)
    {
        $this->timeout = $timeout;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return integer
     */
    public function getTimeout()
    {
        return $this->timeout;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @param string $value
     * @return string
     */
    public function specialUrlEncode(string $value)
    {
        $value = urlencode($value);
        $value = str_replace('+', '%20', $value);
        $value = str_replace('*', '%2A', $value);
        $value = str_replace('%7E', '~', $value);
        return $value;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @param array $params
     * @return static
     */
    public function setSignature(array $params)
    {
        ksort($params);
        $string = '';
        foreach ($params as $key => $value) {
            $string .= '&'. $this->specialUrlEncode($key) .'='. $this->specialUrlEncode($value);
        }
        $string = ltrim($string, '&');
        $this->signature = base64_encode(hash_hmac('sha1', self::METHOD_GET . '&' . $this->specialUrlEncode('/') . '&' . $this->specialUrlEncode($string), $this->getAccessSecret() . '&', true));
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return string
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @param  string $action
     * @return static
     */
    public function setAction(string $action)
    {
        $this->action = $action;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return string
     */
    public function getAction()
    {
        return $this->action;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @param  string $regionId
     * @return static
     */
    public function setRegionId(string $regionId)
    {
        $this->regionId = $regionId;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return string
     */
    public function getRegionId()
    {
        return $this->regionId;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @param string $signatureMethod
     * @return static
     */
    public function setSignatureMethod(string $signatureMethod)
    {
        $this->signatureMethod = $signatureMethod;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return string
     */
    public function getSignatureMethod()
    {
        return $this->signatureMethod;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return static
     */
    private function setSignatureNonce()
    {
        $this->signatureNonce = md5($this->getTimestamp() . rand(10000, 99999));
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return string
     */
    public function getSignatureNonce()
    {
        if (is_null($this->signatureNonce)) {
            $this->setSignatureNonce();
        }
        return $this->signatureNonce;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @param string $signatureVersion
     * @return static
     */
    public function setSignatureVersion(string $signatureVersion)
    {
        $this->signatureVersion = $signatureVersion;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return string
     */
    public function getSignatureVersion()
    {
        return $this->signatureVersion;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @param  string $format
     * @return static
     */
    public function setFormat(string $format)
    {
        $this->format = $format;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return string
     */
    public function getFormat()
    {
        return $this->format;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return string
     */
    public function getDateTime()
    {
        return gmdate('Y-m-d\TH:i:s\Z', $this->getTimestamp());
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return static
     */
    public function setTimestamp()
    {
        $this->timestamp = time();
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return integer
     */
    public function getTimestamp()
    {
        if (is_null($this->timestamp)) {
            $this->setTimestamp();
        }
        return $this->timestamp;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @param string $version
     * @return static
     */
    public function setVersion(string $version)
    {
        $this->version = $version;
        return $this;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月29日
     * @return string
     */
    public function getVersion()
    {
        return $this->version;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月30日
     * @param bool $debug
     */
    public function setDebug(bool $debug)
    {
        $this->debug = $debug;
    }

    /**
     *
     * @author zxf
     * @date   2021年7月30日
     * @return boolean
     */
    public function getDebug()
    {
        return $this->debug === true;
    }
}
