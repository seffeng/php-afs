## ALIYUN AFS

### 安装

```shell
# 安装
$ composer require seffeng/afs
```

### 目录说明

```
├─src
│  │  AfsClient.php
│  ├─Exceptions
│  │    AfsException.php
└─tests
    AfsTest.php
```

### 示例

```php
/**
 * SiteController
 */
use Seffeng\Afs\AfsClient;

class SiteController extends Controller
{
    public function index()
    {
        try {
            $accessKeyId = '';          // 阿里云 AccessKeyId
            $accessSecret = '';         // 阿里云 AccessKeySecret
            $appKey = '';               // 阿里云验证码 appkey

            $ip = '192.168.1.100';      // 客户端IP
            $scene = 'ic_login';        // 使用场景标识，必填参数，可从前端获取 [ic_login, nc_activity_h5, ...]
            $token = '1627557...';      // 请求唯一标识，必填参数，从前端获取
            $sig = '05XqrtZ0Ea...';     // 签名串，必填参数，从前端获取
            $sessionId = '01sWbn...';   // 会话ID，必填参数，从前端获取

            $afs = new AfsClient($accessKeyId, $accessSecret, $appKey);
            $afs->setScene($scene);
            $afs->setToken($token);
            $afs->setSig($sig);
            $afs->setSessionId($sessionId);
            $afs->setRemoteIp($ip);
            var_dump($afs->verify());
        } catch (AfsException $e) {
            echo $e->getMessage();
        } catch (\Exception $e) {
            echo $e->getMessage();
        }
    }
}
```

### 备注

1、暂只支持滑动验证和智能验证；不支持无痕验证。