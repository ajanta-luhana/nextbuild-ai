from __future__ import annotations


class AppError(Exception):
    status = 500
    code = "INTERNAL_ERROR"

    def __init__(self, message: str, details: list[dict] | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or []


class ValidationFailed(AppError):
    status, code = 422, "VALIDATION_ERROR"


class NotFound(AppError):
    status, code = 404, "NOT_FOUND"


class Forbidden(AppError):
    status, code = 403, "FORBIDDEN"


class Unauthenticated(AppError):
    status, code = 401, "UNAUTHENTICATED"


class Conflict(AppError):
    status, code = 409, "INVALID_STATE"


class RateLimited(AppError):
    status, code = 429, "RATE_LIMITED"
