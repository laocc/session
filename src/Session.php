<?php
declare(strict_types=1);

namespace esp\session;

use \Error;
use \Redis;
use esp\session\handler\HandlerFile;
use esp\session\handler\HandlerRedis;
use function esp\helper\host;


/**
 * Class Session
 * @package plugins\ext
 */
final class Session
{
    private $SessionHandler;

    public function __construct(array $config)
    {
        $config += [
            'drive' => 'redis',//驱动方式：redis,file
            'key' => 'PHPSESSID',//session在cookies中的名称
            'delay' => 0,//是否自动延期
            'prefix' => '',//session保存在redis或file中的键名前缀
            'path' => '/',//设定会话 cookie 的路径，一般就为网站根目录，也可以指定如：/admin
            'domain' => 'host',//host或domain；在host还是域名下有效，见下面说明
            'limiter' => 'nocache',//客户端缓存方法，没太明白这个
            'expire' => 86400,//session保存时间，在redis时，过了这个时间就删除，file下无作用
            'cookie' => 86400,//客户端cookies保存时间

            //redis的连接方式
            'redis' => [
                'host' => '127.0.0.1',
                'port' => 6379,
                'db' => 0,
                'password' => '',
            ]
        ];
        if ($config['cookie'] < $config['expire']) $config['cookie'] = $config['expire'];
        $option = [];

        if ($config['drive'] === 'file') {
            $option['save_path'] = serialize($config['path']);//在handlerFile->open()的第1个参数即是此值
            $this->SessionHandler = new HandlerFile(boolval($config['delay']), $config['prefix']);

        } else {
            $option['save_path'] = serialize($config['redis']);//这里送入redis的配置，在handlerRedis->open()的第1个参数即是此值
            $this->SessionHandler = new HandlerRedis(boolval($config['delay']), $config['prefix']);
        }
        $handler = session_set_save_handler($this->SessionHandler, true);
        if (!$handler) throw new Error('session_set_save_handler Error');

        $option['serialize_handler'] = 'php_serialize';//用PHP序列化存储数据

        //指定会话名以用做 cookie 的名字。只能由字母数字组成，默认为 PHPSESSID，handlerRedis->open()的第2个参数
        $option['name'] = strtolower($config['key']);

        //若为nocache以外值，则Last-Modified为index.php最后保存时间，不知道为什么要显示成这个时间
        $option['cache_limiter'] = $config['limiter'];//客户端缓存方法
        $option['cache_expire'] = intval($config['expire'] / 60);//缓存方法内容生命期，分钟

        $option['use_trans_sid'] = $config['use_trans_sid'] ?? 0;//指定是否启用透明 SID 支持。默认为 0（禁用）。
        $option['use_only_cookies'] = 1;//指定是否在客户端仅仅使用 cookie 来存放会话 ID。。启用此设定可以防止有关通过 URL 传递会话 ID 的攻击
        $option['use_cookies'] = 1;//指定是否在客户端用 cookie 来存放会话 ID

        $option['cookie_lifetime'] = intval($config['cookie']);//以秒数指定了发送到浏览器的 cookie 的生命周期。值为 0 表示"直到关闭浏览器"。
        $option['cookie_path'] = $config['path'];//指定了要设定会话 cookie 的路径。默认为 /。
        $option['cookie_secure'] = (getenv('HTTP_HTTPS') === 'on' or getenv('HTTPS') === 'on');//指定是否仅通过安全连接发送 cookie。默认为 off。如果启用了https则要启用
        $option['cookie_httponly'] = true;//只能PHP读取，JS禁止

        $domain = explode(':', getenv('HTTP_HOST') . ':')[0];
        if ($config['domain'] === 'host') {
            $config['domain'] = host($domain);
        } else if ($config['domain'] === 'domain') {
            $config['domain'] = $domain;
        }

        /**
         * 有域名www.abc.com和abc.com
         * cookie_domain=www.abc.com或abc.com
         * 若为后者，则在 *.abc.com 下都能读取
         * 若为前者，则只在 www.abc.com 下能读取
         */
        $option['cookie_domain'] = $config['domain'];

        if (version_compare(PHP_VERSION, '7.3', '>=')) $option['cookie_samesite'] = 'Lax';

        //允许从URL或POST中读取session值
        if ($option['use_trans_sid']) {
            $ptn = "/^{$config['prefix']}[\w\-]{22,32}$/";
            if ((isset($_GET[$option['name']]) and preg_match($ptn, $_GET[$option['name']]))
                or
                (isset($_POST[$option['name']]) and preg_match($ptn, $_POST[$option['name']]))
            ) {
                session_id($_GET[$option['name']]);
            }
        }

        $star = session_start($option);
        if (!$star) throw new Error('session_start Error');
    }

    /**
     * 在redis的时候，送入已连接好的Redis对象
     *
     * @param Redis $redis
     * @return bool
     */
    public function setRedis(Redis $redis): bool
    {
        return $this->SessionHandler->setDrive($redis);
    }


    /**
     * 设置或读取过期时间
     * @param int|null $ttl
     * @return bool|int
     */
    public function ttl(int $ttl = null)
    {
        return $this->SessionHandler->ttl($ttl);
    }

    /**
     * 换新的sessionID
     * @param bool $createNew 换新ID后，原数据清空，一般都要清空，否则会导至数据库暴增
     * @return string
     */
    public function id(bool $createNew = false): string
    {
        if ($createNew) session_regenerate_id(true);
        return session_id();
    }

    /**
     * 设置某值，同时重新设置有效时间
     *
     * @param $key
     * @param null $value
     * @return Session
     */
    public function set($key, $value = null): Session
    {
        if (is_array($key)) {
            foreach ($key as $k => $v) {
                $_SESSION[$k] = $v;
            }
        } else {
            $_SESSION[$key] = $value;
        }
        return $this;
    }

    /**
     * 读取一个值，可以直接读 $_SESSION[$key]
     *
     * @param $key
     * @param null $autoValue
     * @return mixed
     */
    public function get($key, $autoValue = null)
    {
        if ($key === null) return null;
        if (empty($_SESSION)) return null;
        if (!isset($_SESSION[$key])) return $autoValue;
        $value = $_SESSION[$key];
        if (is_null($autoValue)) return $value;

        if (is_string($autoValue)) $value = strval($value);
        else if (is_int($autoValue)) $value = intval($value);
        else if (is_bool($autoValue)) $value = boolval($value);
        else if (is_float($autoValue)) $value = floatval($value);
        else if (is_array($autoValue) and !is_array($value)) $value = json_decode($value, true);

        return $value;
    }

    /**
     * 删除某一项，可以同时删除多个，建议直接
     * $_SESSION[$key] = null;
     * 或
     * unset($_SESSION[$key]);
     *
     * @param string ...$keys
     * @return Session
     */
    public function del(string ...$keys): Session
    {
        foreach ($keys as $key) $_SESSION[$key] = null;
        return $this;
    }

    /**
     * @param string $key
     * @param null $val
     * @return bool|mixed|string|null
     */
    public function data(string $key, $val = null)
    {
        if (is_null($val)) {
            $value = $_SESSION[$key] ?? '';
            if (empty($value) or !is_array($value)) return null;
            return $value['val'] ?? null;

        } else if ($val === false) {
            $_SESSION[$key] = null;

        } else if (is_array($val)) {
            $_SESSION[$key] = $val;

        } else {
            $value = [];
            $value['val'] = $val;
            $value['time'] = time();
            $_SESSION[$key] = $value;
        }
        return true;
    }

    /**
     * 清空session
     */
    public function empty(): bool
    {
        $_SESSION = [];
        return session_destroy();
    }

    /**
     * 以下两个方法在实际应用中，直接调用相应函数就可以了
     *
     * 撤销本次请求对session的改动
     * @return bool
     */
    public function reset(): bool
    {
        return session_abort();
    }

    /**
     * 结束session
     */
    public function destroy(): bool
    {
        return session_destroy();
    }

}

