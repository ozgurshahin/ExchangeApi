from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class GetExchangeRateResponse:
    conversion_rate: str
    base_code: str
    target_code: str
