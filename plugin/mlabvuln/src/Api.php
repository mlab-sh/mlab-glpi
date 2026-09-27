<?php

namespace GlpiPlugin\Mlabvuln;

use GuzzleHttp\Pool;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;
use Throwable;
use Toolbox;

/**
 * Thin client for vuln.mlab.sh. Any non-2xx throws: a 5xx is an outage, never "clean".
 * Calls take ~1 s each, so bulk lookups go through many() with bounded concurrency.
 */
final class Api
{
    private const CONCURRENCY = 8;

    private \GuzzleHttp\Client $http;

    public function __construct(private string $base, string $token = '')
    {
        $headers = ['User-Agent' => 'mlab-glpi/' . PLUGIN_MLABVULN_VERSION, 'Accept' => 'application/json'];
        if ($token !== '') {
            $headers['Authorization'] = 'Bearer ' . $token;
        }
        $this->http = Toolbox::getGuzzleClient([
            'timeout'     => 60,
            'http_errors' => false,
            // the API rejects default library user-agents (403)
            'headers'     => $headers,
        ]);
    }

    private function url(string $path): string
    {
        return rtrim($this->base, '/') . $path;
    }

    private function decode(ResponseInterface $res, string $path): array
    {
        $code = $res->getStatusCode();
        if ($code === 404) {
            return [];
        }
        if ($code === 401 || $code === 403) {
            throw new RuntimeException("vuln.mlab.sh $path: HTTP $code, token API invalide ou expiré");
        }
        if ($code < 200 || $code >= 300) {
            throw new RuntimeException("vuln.mlab.sh $path: HTTP $code");
        }
        return json_decode((string) $res->getBody(), true, flags: JSON_THROW_ON_ERROR);
    }

    private function call(string $method, string $path, array $opts = []): array
    {
        for ($try = 0; ; $try++) {
            $res = $this->http->request($method, $this->url($path), $opts);
            if ($res->getStatusCode() === 429 && $try < 3) {
                sleep(min(60, (int) ($res->getHeaderLine('Retry-After') ?: 5)));
                continue;
            }
            return $this->decode($res, $path);
        }
    }

    /**
     * Run requests concurrently. $requests: key => [method, path, opts].
     * @return array key => decoded array | Throwable
     */
    private function many(array $requests, ?callable $each = null): array
    {
        $keys = array_keys($requests);
        $out = $throttled = [];
        $gen = function () use ($requests) {
            foreach ($requests as [$method, $path, $opts]) {
                yield fn() => $this->http->requestAsync($method, $this->url($path), $opts);
            }
        };
        (new Pool($this->http, $gen(), [
            'concurrency' => self::CONCURRENCY,
            'fulfilled'   => function (ResponseInterface $res, int $i) use ($keys, $requests, $each, &$out, &$throttled) {
                $k = $keys[$i];
                if ($res->getStatusCode() === 429) {
                    $throttled[] = $k;
                    return;
                }
                try {
                    $out[$k] = $this->decode($res, $requests[$k][1]);
                } catch (Throwable $e) {
                    $out[$k] = $e;
                }
                if ($each) {
                    $each($k, $out[$k]);
                    unset($out[$k]);
                }
            },
            'rejected'    => function ($reason, int $i) use ($keys, $each, &$out) {
                $k = $keys[$i];
                $out[$k] = $reason instanceof Throwable ? $reason : new RuntimeException((string) $reason);
                if ($each) {
                    $each($k, $out[$k]);
                    unset($out[$k]);
                }
            },
        ]))->promise()->wait();

        // rate-limited ones: sequential, honouring Retry-After
        foreach ($throttled as $k) {
            try {
                $out[$k] = $this->call(...$requests[$k]);
            } catch (Throwable $e) {
                $out[$k] = $e;
            }
            if ($each) {
                $each($k, $out[$k]);
                unset($out[$k]);
            }
        }
        return $out;
    }

    /**
     * OSV lookups. $queries: key => [ecosystem, name, version].
     * @return array key => list of OSV vulns | Throwable
     */
    public function osvMany(array $queries): array
    {
        $req = array_map(fn($q) => ['POST', '/api/v2/query', ['json' => [
            'package' => ['name' => $q[1], 'ecosystem' => $q[0]],
            'version' => $q[2],
        ]]], $queries);
        return array_map(fn($r) => $r instanceof Throwable ? $r : ($r['vulns'] ?? []), $this->many($req));
    }

    /** @return array CVE id => detail array (empty if unknown) | Throwable */
    public function cveMany(array $ids): array
    {
        $req = [];
        foreach ($ids as $id) {
            $req[$id] = ['GET', '/api/v1/cve/' . rawurlencode($id), []];
        }
        return $this->many($req);
    }

    /**
     * Stream every result of a full-text search (0-based pages of 100) to $each, page by page:
     * Chrome is ~70 pages, keeping them all decoded costs 200 MB.
     */
    public function searchAll(string $q, int $max_pages, callable $each): void
    {
        $first = $this->call('GET', '/api/v1/cve', ['query' => ['q' => $q, 'limit' => 100, 'page' => 0]]);
        array_map($each, $first['cves'] ?? []);
        $pages = min($max_pages, (int) ceil(($first['total_results'] ?? 0) / 100));
        $req = [];
        for ($p = 1; $p < $pages; $p++) {
            $req[$p] = ['GET', '/api/v1/cve', ['query' => ['q' => $q, 'limit' => 100, 'page' => $p]]];
        }
        $error = null;
        $this->many($req, function ($k, $page) use ($each, &$error) {
            if ($page instanceof Throwable) {
                $error ??= $page;
                return;
            }
            array_map($each, $page['cves'] ?? []);
        });
        if ($error) {
            throw $error; // partial product data would silently hide CVEs
        }
    }
}
