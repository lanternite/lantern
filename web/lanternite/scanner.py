import os

import httpx


class ScannerClient:
    def __init__(self):
        self.base_url = os.environ.get("SCANNER_API_URL", "http://127.0.0.1:8000").rstrip("/")
        self.token = os.environ.get("SCANNER_API_TOKEN", "")

    def _request(self, method, path, **kwargs):
        try:
            res = httpx.request(
                method,
                f"{self.base_url}{path}",
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=httpx.Timeout(90.0, connect=5.0),
                **kwargs,
            )
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as e:
            try:
                raise RuntimeError(e.response.json().get("detail", "scanner error"))
            except (ValueError, AttributeError):
                raise RuntimeError("scanner error")
        except (httpx.RequestError, ValueError):
            raise RuntimeError("scanner offline")

    def add_image(self, work_id, filename, data, content_type):
        return self._request(
            "POST",
            "/v1/app/works/image",
            data={"work_id": work_id},
            files={"image": (filename, data, content_type or "application/octet-stream")},
        )

    def matches(self, work_id):
        return self._request("GET", "/v1/app/matches", params={"work_id": work_id})

    def delete_work(self, work_id):
        return self._request("DELETE", f"/v1/app/works/{work_id}")

    def exact_hash(self, pdq_hex):
        return self._request("GET", "/v1/app/search/hash", params={"pdq_hex": pdq_hex})

    def search_image(self, filename, data, content_type):
        return self._request(
            "POST",
            "/v1/app/search/image",
            files={"image": (filename, data, content_type or "application/octet-stream")},
        )
