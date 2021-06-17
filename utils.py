# -*- coding: utf-8 -
from requests.api import get
import base64
import jinja2
import os
import re
import requests as r
import time
import xmltodict
import yaml

from config import API_BASE_URL, TEST
from signer import create_jwt_via_api
from log import logger


def ordereddict_to_dict(ordered_dict):
    """
    Конвертация OrderedDict в dict, включае вложенные элементы.
    """
    for k, v in ordered_dict.items():
        if isinstance(v, dict):
            ordered_dict[k] = ordereddict_to_dict(v)
    return dict(ordered_dict)


def lower_dict_keys(d: dict) -> dict:
    """
    Перевести в нижний регистр ключи словаря.
    """
    result = {}
    for key, value in d.items():
        try:
            result[key.lower()] = value
        except AttributeError:
            result[key] = value
    return result


def is_base64(sb) -> bool:
    """
    Это Base64 строка?
    """
    try:
        if isinstance(sb, str):
            sb_bytes = bytes(sb, "ascii")
        elif isinstance(sb, bytes):
            sb_bytes = sb
        else:
            raise ValueError("Argument must be string or bytes")
        return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
    except Exception:
        return False


def safe_split(s: str, sep: str) -> list:
    """
    Безопасный split
    """
    res = []
    try:
        res = s.split(sep)
    except:
        ...
    return res


def decode_str_to_utf8(s: str) -> str:
    """
    Декодирование строки в UTF-8.
    """
    try:
        return bytes(s, "iso-8859-1").decode("utf-8")
    except:
        return s


def decode_base64_dict_to_utf8(d: dict) -> dict:
    """
    Декодирование словаря c JWT строками в UTF-8
    """
    d_values = list(d.values())
    if not d_values:
        raise ValueError("Неверный словарь на входе!")
    s_split = safe_split(d_values[0], sep=".")[:-1]
    return {
        "header": yaml.safe_load(base64.b64decode(s_split[0]).decode("utf-8")),
        "payload": base64.b64decode(s_split[1]).decode("utf-8"),
    }


def get_sprav_by_name(name: str) -> str:
    """
    Получение справочников.

    """
    resp = r.post(
        f"{TEST['BASE_URL']}/api/cls/request",
        json={
            "cls": name,
            "ogrn": TEST["OGRN"],
            "kpp": TEST["KPP"],
        },
        headers={"Content-Type": "application/json"},
    )
    return resp.text


def check_binding_cert_to_org() -> str:
    """
    Проверка привязки сертификата к организации,
    а также корректной подписи данных.
    """
    header = {"ogrn": TEST["OGRN"], "kpp": TEST["KPP"]}
    jwt = create_jwt_via_api(header=header)
    resp = r.post(
        f"{TEST['BASE_URL']}/api/certificate/check",
        json={
            "token": jwt,
        },
        headers={"Content-Type": "application/json"},
    )
    return resp.json()


def get_data(entity_type: str, uid: str) -> str:
    """
    Получение записи из системы.
    """
    header = {
        "action": "get",
        "entityType": entity_type,
        "ogrn": TEST["OGRN"],
        "kpp": TEST["KPP"],
    }
    payload = f"<PackageData><{entity_type[0].upper() + entity_type[1:]}><UID>{uid}</UID></{entity_type[0].upper() + entity_type[1:]}></PackageData>"
    jwt = create_jwt_via_api(header=header, payload=payload)
    resp = r.post(
        f"{TEST['BASE_URL']}/api/token/new",
        json={
            "token": jwt,
        },
        headers={"Content-Type": "application/json"},
    )
    try:
        return resp.json()["idJwt"]
    except:
        logger.error(resp.text)
        return None


def remove_data(entity_type: str, uid: str) -> str:
    """
    Удаление записи из СС.
    """
    header = {
        "action": "remove",
        "entityType": entity_type,
        "ogrn": TEST["OGRN"],
        "kpp": TEST["KPP"],
    }
    payload = f"<PackageData><{entity_type[0].upper() + entity_type[1:]}><UID>{uid}</UID></{entity_type[0].upper() + entity_type[1:]}></PackageData>"
    jwt = create_jwt_via_api(header=header, payload=payload)
    resp = r.post(
        f"{TEST['BASE_URL']}/api/token/new",
        json={
            "token": jwt,
        },
        headers={"Content-Type": "application/json"},
    )
    try:
        return resp.json()["idJwt"]
    except:
        logger.error(resp.text)
        return None


def modify_data(action: str, entity_type: str, payload: str) -> str:
    """
    Модификация данных в системе.

    Параметры
    ---------
    action : str
        Действие: Add, Edit
    entity_type : str
        Тип сущности:
        admissionVolume, appAchievement, applicationsRating,
        campaign, cmpAchievement, competitiveBenefit, competitiveGroup,
        competitiveGroupApplicationsList, competitiveGroupProgram,
        competitiveGroupSpecialty, contract, distributedAdmissionVolume,
        document, editApplicationStatusList, educationProgram, entranceTest,
        entranceTestAgreedList, entranceTestBenefit, entranceTestLocation,
        entranceTestResultList, entranceTestSheet, identification,
        orderAdmissionList, orgDirection, restartDocumentCheckList,
        sentToEpguEtc, serviceApplication, serviceEntrant, serviceEntrantPhotoFile,
        subdivisionOrg, termsAdmission.

    payload : str
        Данные в формате XML, соответствующие action и entity_type.
    """
    header = {
        "action": action,
        "entityType": entity_type,
        "ogrn": TEST["OGRN"],
        "kpp": TEST["KPP"],
    }
    jwt = create_jwt_via_api(header=header, payload=payload)
    resp = r.post(
        f"{TEST['BASE_URL']}/api/token/new",
        json={
            "token": jwt,
        },
        headers={"Content-Type": "application/json"},
    )
    try:
        return resp.json()["idJwt"]
    except:
        logger.error(resp.text)
        return None


def get_info_from_query(id_jwt: int = 0, get_all_messages=False, queue="service"):
    """
    Получить статус обработки из очереди.

    Параметры
    ---------

    id_jwt: int
        ID токена, полученного от системы.
        При id_jwt = 0 (по умолчанию) возвращается следующее сообщение из очереди.

    get_number_only: bool
        Флаг: проверить только наличия сообщений в очереди и вывести их

    queue: str
        Имя очереди, с которой осуществляется работа.
        Варианты: service, epgu.
    """
    if not get_all_messages:
        header = {
            "action": "getMessage",
            "ogrn": TEST["OGRN"],
            "kpp": TEST["KPP"],
            "idJwt": id_jwt,
        }
        resp = r.post(
            f"{TEST['BASE_URL']}/api/token/{queue}/info",
            json={
                "token": create_jwt_via_api(header=header),
            },
            headers={"Content-Type": "application/json"},
        )
    else:
        resp = r.post(
            f"{TEST['BASE_URL']}/api/token/{queue}/info",
            json={
                "ogrn": TEST["OGRN"],
                "kpp": TEST["KPP"],
            },
            headers={"Content-Type": "application/json"},
        )
    try:
        return resp.json()
    except:
        logger.error(resp.text)
        return None



def entity(action: str, entity_type: str, record: dict = None):
    """
    Работа с сущностями в СС.

    Параметры
    ---------
    action: str
        Действие: add, edit, get, remove

    entity_type: str
        Тип сущности:
        subdivisionOrg (кафедра) - vw$ss_subdivisionorg_2021;
        educationProgram (образовательная программа) - vw$ss_educationprogram_2021;
        campaign (приемная кампания) - vw$ss_campaign_2021;
        cmpAchievement (индивидуальное достижение, учитываемое в рамках приемной кампании | не исп.) - ss_cmpachievement;
        admissionVolume (кцп) - vw$ss_admissionvolume_2021;
        distributedAdmissionVolume (распределение кцп по уровням бюджета) - vw$ss_distadmissionvolume_2021;
        termsAdmission (мероприятия в рамках приемной кампании) - vw$ss_termsadmission_2021_189;
        competitiveGroup (конкурсная группа) - vw$ss_competitivegroup_2021;
        competitiveGroupProgram (связь образовательной программы с конкурсом) - vw$ss_competitivegrouppr_2021;
        competitiveBenefit (льготы, учитываемые в кг) - vw$ss_competitivebenefit_2021;
        entranceTest (вступительные испытания в рамках кг) - vw$ss_entrancetest_2021;
        entranceTestBenefit (льготы в рамках ви | не исп.) - vw$ss_entrancetestbenefit_2021;
        entranceTestLocation (дата и место ви) - vw$ss_entrancetestloc_2021

    record: dict
        Запись для манипуляции данных
    """
    if entity_type not in (
        "subdivisionOrg",
        "educationProgram",
        "campaign",
        "cmpAchievement",
        "admissionVolume",
        "distributedAdmissionVolume",
        "termsAdmission",
        "competitiveGroup",
        "competitiveGroupProgram",
        "competitiveBenefit",
        "entranceTest",
        "entranceTestBenefit",
        "entranceTestLocation",
    ):
        raise ValueError(
            f"entity_type {entity_type} не поддерживается, проверьте название сущности!"
        )

    if action not in ("add", "edit", "get", "remove"):
        raise ValueError(
            "Вы можете использовать только действия add, edit, get, remove!"
        )

    if isinstance(record, dict):
        record_lower = lower_dict_keys(record)
    else:
        raise ValueError("Запись record должна быть типа dict!")

    uid = record_lower.get("uid")
    if not uid:
        raise ValueError("uid не входит в словарь record!")

    if action in ("get", "remove"):
        if action == "get":
            id_jwt = get_data(entity_type=entity_type, uid=uid)
            if not id_jwt:
                raise ValueError(
                    "Что-то пошло не так с получением данных, посмотрите лог!"
                )
            time.sleep(0.2)
            info = get_info_from_query(id_jwt=int(id_jwt))
            if info.get("error"):
                logger.error(
                    f"Данные еще не поступили в очередь ({entity_type} | {action} | {id_jwt}) или очередь недоступна"
                )
                return {
                    "status": "unknown",
                    "id_jwt": id_jwt,
                    "entity_type": None,
                    "data": None,
                }
            data = decode_base64_dict_to_utf8(info)
            if data["header"].get("payloadType") == "success":
                return {
                    "status": "success",
                    "id_jwt": id_jwt,
                    "entity_type": data["header"].get("subdivisionOrg"),
                    "data": ordereddict_to_dict(xmltodict.parse(data["payload"]))[
                        "PackageData"
                    ][f"{entity_type[0].upper() + entity_type[1:]}"],
                }
            else:
                logger.info(f"{id_jwt} -- {data['payload']}")
                return {
                    "status": "failure",
                    "id_jwt": id_jwt,
                    "entity_type": data["header"].get("subdivisionOrg"),
                    "data": None,
                }
        if action == "remove":
            id_jwt = remove_data(entity_type=entity_type, uid=uid)
            if not id_jwt:
                raise ValueError(
                    "Что-то пошло не так с удалением данных, посмотрите лог!"
                )
            time.sleep(0.2)
            info = get_info_from_query(id_jwt=int(id_jwt))
            if info.get("error"):
                logger.error(
                    f"Данные еще не поступили в очередь ({entity_type} | {action} | {id_jwt}) или очередь недоступна"
                )
                return {
                    "status": "unknown",
                    "id_jwt": id_jwt,
                    "entity_type": None,
                    "data": None,
                }
            data = decode_base64_dict_to_utf8(info)
            if data["header"].get("payloadType") == "success":
                return {
                    "status": "success",
                    "id_jwt": id_jwt,
                    "entity_type": data["header"].get("entityType"),
                    "data": None,
                }
            else:
                logger.info(f"{id_jwt} -- {data['payload']}")
                return {
                    "status": "failure",
                    "id_jwt": id_jwt,
                    "entity_type": data["header"].get("subdivisionOrg"),
                    "data": None,
                }
    elif action in ("add", "edit"):
        if not record:
            raise ValueError("Нет записи record для добавления или модификации данных!")
        record_lower = lower_dict_keys(record)
        with open(os.path.join("schemas", "payload", entity_type, "template.xml")) as f:
            file = f.read()
        temp = jinja2.Template(file)
        payload_raw = temp.render(**record_lower)
        payload = re.sub(r"\s+", "", payload_raw)
        if action == "add":
            id_jwt = modify_data(
                action=action, entity_type=entity_type, payload=payload
            )
            if not id_jwt:
                raise ValueError(
                    "Что-то пошло не так с добавлением данных, посмотрите лог!"
                )
            time.sleep(0.2)
            info = get_info_from_query(id_jwt=int(id_jwt))
            if info.get("error"):
                logger.warning(
                    f"Данные еще не поступили в очередь ({entity_type} | {action} | {id_jwt}) или очередь недоступна"
                )
                return {
                    "status": "unknown",
                    "id_jwt": id_jwt,
                    "entity_type": None,
                    "data": None,
                }
            data = decode_base64_dict_to_utf8(info)
            if data["header"].get("payloadType") == "success":
                return {
                    "status": "success",
                    "id_jwt": id_jwt,
                    "entity_type": data["header"].get("entityType"),
                    "data": None,
                }
            else:
                logger.info(f"{id_jwt} -- {data['payload']}")
                return {
                    "status": "failure",
                    "id_jwt": id_jwt,
                    "entity_type": data["header"].get("entityType"),
                    "data": None,
                }
        if action == "edit":
            id_jwt = modify_data(
                action=action, entity_type=entity_type, payload=payload
            )
            if not id_jwt:
                raise ValueError(
                    "Что-то пошло не так с модификацией данных, посмотрите лог!"
                )
            time.sleep(0.2)
            info = get_info_from_query(id_jwt=int(id_jwt))
            if info.get("error"):
                logger.warning(
                    f"Данные еще не поступили в очередь ({entity_type} | {action} | {id_jwt}) или очередь недоступна"
                )
                return {
                    "status": "unknown",
                    "id_jwt": id_jwt,
                    "entity_type": None,
                    "data": None,
                }
            data = decode_base64_dict_to_utf8(info)
            if data["header"].get("payloadType") == "success":
                return {
                    "status": "success",
                    "id_jwt": id_jwt,
                    "entity_type": data["header"].get("entityType"),
                    "data": None,
                }
            else:
                logger.info(f"{id_jwt} -- {data['payload']}")
                return {
                    "status": "failure",
                    "id_jwt": id_jwt,
                    "entity_type": data["header"].get("entityType"),
                    "data": None,
                }


def confirm_of_getting_data(id_jwt: int):
    """
    Подтверждение получение сообщения из очереди

    Параметры
    ---------

    id_jwt: int
        ID токена, полученного от системы.
        При id_jwt = 0 (по умолчанию) возвращается следующее сообщение из очереди.
    """
    header = {
        "action": "messageConfirm",
        "ogrn": TEST["OGRN"],
        "kpp": TEST["KPP"],
        "idJwt": id_jwt,
    }
    jwt = create_jwt_via_api(header=header)
    resp = r.post(
        f"{TEST['BASE_URL']}/api/token/confirm",
        json={
            "token": jwt,
        },
        headers={"Content-Type": "application/json"},
    )
    return resp.json()


def confirm_all(queue="service"):
    """
    Подтвердить все сообжения в очереди

    Параметры
    ---------

    queue: str
        Имя очереди, с которой осуществляется работа.
        Варианты: service, egpu.
    """
    message_data = get_info_from_query(get_all_messages=True)
    id_jwt_list = message_data.get("idJwts")

    if id_jwt_list:
        for id_jwt in id_jwt_list:
            query_data = get_info_from_query(id_jwt=id_jwt,  queue=queue)
            confirm_data = confirm_of_getting_data(id_jwt=id_jwt)
            s = f"{id_jwt} -- {decode_base64_dict_to_utf8(query_data)} -- {confirm_data}"
            logger.info(s)
        return True
    else:
        print(f"{queue.capitalize()} queue is empty!")
        return False


def get_data_from_db(entity_type: str, skip: int = 0, limit: int = 20000, stage: int = None) -> list:
    if entity_type not in (
        "subdivisionOrg",
        "educationProgram",
        "campaign",
        "cmpAchievement",
        "admissionVolume",
        "distributedAdmissionVolume",
        "termsAdmission",
        "competitiveGroup",
        "competitiveGroupProgram",
        "competitiveBenefit",
        "entranceTest",
        "entranceTestBenefit",
        "entranceTestLocation",
    ):
        raise ValueError(
            f"entity_type {entity_type} не поддерживается, проверьте название сущности!"
        )

    translator = {
        "subdivisionOrg": "/api/db/get-subdivision-org",
        "educationProgram": "/api/db/get-education-program",
        "campaign": "/api/db/get-campaign",
        "cmpAchievement": "/api/db/get-cmp-achievement",
        "admissionVolume": "/api/db/get-admission-volume",
        "distributedAdmissionVolume": "/api/db/get-distributed-admission-volume",
        "termsAdmission": "/api/db/get-terms-admission",
        "competitiveGroup": "/api/db/get-competitive-group",
        "competitiveGroupProgram": "/api/db/get-competitive-group-program",
        "competitiveBenefit": "/api/db/get-competitive-benefit",
        "entranceTest": "/api/db/get-entrance-test",
        "entranceTestBenefit": "/api/db/get-entrance-test-benefit",
        "entranceTestLocation": "/api/db/get-entrance-test-location",
    }

    if entity_type == "entranceTest":
        resp = r.get(
            f"{API_BASE_URL}{translator[entity_type]}",
            params={'skip': skip, 'limit': limit, 'stage': stage},
            headers={"Content-Type": "application/json"},
        )
        try:
            return resp.json()
        except:
            logger.error(resp.text)
            return None
    
    resp = r.get(
        f"{API_BASE_URL}{translator[entity_type]}",
        params={'skip': skip, 'limit': limit},
        headers={"Content-Type": "application/json"},
    )
    try:
        return resp.json()
    except:
        logger.error(resp.text)
        return None


if __name__ == "__main__":
    print(
        entity(
            action="get",
            entity_type="termsAdmission",
            record={"UID": 2609534405},
        )
    )
    # confirm_all()
    # print(get_info_from_query(get_all_messages=False, queue='epgu'))
    # print(get_data('subdivisionOrg', '2157296801'))
    # print(get_info_from_query(get_all_messages=False, queue='service', id_jwt=1068437))
    # d = get_data_from_db(entity_type='campaign')
    # for el in d:
    #     print(el)
    #     print(entity(action="get", entity_type="campaign", record=el))
    # confirm_all()

    print(decode_str_to_utf8(get_sprav_by_name(name='TermsAdmissionMatches')))

