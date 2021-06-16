import requests as r
import json

from config import API_BASE_URL


def create_jwt_via_api(header: dict, payload: str = None) -> str:
    """
    Получить JWT для запроса к API сервиса приема ССПВО.
    """
    header_dump = json.dumps(header)
    resp = r.post(
        f"{API_BASE_URL}/api/utils/create-jwt",
        json={"header": header_dump, "payload": payload},
        headers={"Content-Type": "application/json"},
    )
    return resp.json()["jwt"]
