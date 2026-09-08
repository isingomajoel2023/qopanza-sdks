<?php

declare(strict_types=1);

namespace Qopanza;

use RuntimeException;

/**
 * Any non-2xx response, or a transport failure.
 *
 * The status code is kept separate from the message so callers can branch
 * on it — a 409 from a revoked key needs different handling from a 429
 * from a rate limit. A status of 0 means the request never reached the
 * API at all.
 */
final class QopanzaApiException extends RuntimeException
{
    private int $statusCode;
    private string $detail;

    public function __construct(int $statusCode, string $detail)
    {
        parent::__construct(sprintf('qopanza: [%d] %s', $statusCode, $detail));
        $this->statusCode = $statusCode;
        $this->detail = $detail;
    }

    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    public function getDetail(): string
    {
        return $this->detail;
    }
}
