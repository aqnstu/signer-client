# -*- coding: utf-8 -
import base64
import json
import jinja2
from nested_lookup import nested_lookup
import os
import requests as r
import time
import xmltodict
import yaml

from config import API_BASE_URL, SS
from db import session
from log import logger
from models import Datatype, Jwt, JwtJob, JwtJson, JwtDoc, t_vw_jwt_to_nstu, t_vw_jwt_doc_to_nstu
from signer import create_jwt_via_api


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
    if d.get('error'):
        print(f"decode_base64_dict_to_utf8: {d}")
        return None
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
        f"{SS['BASE_URL']}/api/cls/request",
        json={
            "cls": name,
            "ogrn": SS["OGRN"],
            "kpp": SS["KPP"],
        },
        headers={"Content-Type": "application/json"},
    )
    return resp.text


def check_binding_cert_to_org() -> str:
    """
    Проверка привязки сертификата к организации,
    а также корректной подписи данных.
    """
    header = {"ogrn": SS["OGRN"], "kpp": SS["KPP"]}
    jwt = create_jwt_via_api(header=header)
    resp = r.post(
        f"{SS['BASE_URL']}/api/certificate/check",
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
        "ogrn": SS["OGRN"],
        "kpp": SS["KPP"],
    }
    payload = f"<PackageData><{entity_type[0].upper() + entity_type[1:]}><UID>{uid}</UID></{entity_type[0].upper() + entity_type[1:]}></PackageData>"
    jwt = create_jwt_via_api(header=header, payload=payload)
    resp = r.post(
        f"{SS['BASE_URL']}/api/token/new",
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
        "ogrn": SS["OGRN"],
        "kpp": SS["KPP"],
    }
    payload = f"<PackageData><{entity_type[0].upper() + entity_type[1:]}><UID>{uid}</UID></{entity_type[0].upper() + entity_type[1:]}></PackageData>"
    jwt = create_jwt_via_api(header=header, payload=payload)
    resp = r.post(
        f"{SS['BASE_URL']}/api/token/new",
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
        "ogrn": SS["OGRN"],
        "kpp": SS["KPP"],
    }
    jwt = create_jwt_via_api(header=header, payload=payload)
    resp = r.post(
        f"{SS['BASE_URL']}/api/token/new",
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
            "ogrn": SS["OGRN"],
            "kpp": SS["KPP"],
            "idJwt": id_jwt,
        }
        resp = r.post(
            f"{SS['BASE_URL']}/api/token/{queue}/info",
            json={
                "token": create_jwt_via_api(header=header),
            },
            headers={"Content-Type": "application/json"},
        )
    else:
        resp = r.post(
            f"{SS['BASE_URL']}/api/token/{queue}/info",
            json={
                "ogrn": SS["OGRN"],
                "kpp": SS["KPP"],
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
            if not data:
                raise ValueError(
                    'Результаты обработки отсутствуют для данного id_jwt!'
                )
            if data["header"].get("payloadType") == "success":
                return {
                    "status": "success",
                    "id_jwt": id_jwt,
                    "entity_type": data["header"].get("entityType"),
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
            if not data:
                raise ValueError(
                    'Результаты обработки отсутствуют для данного id_jwt!'
                )
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
        payload = temp.render(**record_lower)
        # payload = re.sub(r"\s+", "", payload_raw)
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
            if not data:
                raise ValueError(
                    'Результаты обработки отсутствуют для данного id_jwt!'
                )
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
            if not data:
                raise ValueError(
                    'Результаты обработки отсутствуют для данного id_jwt!'
                )
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
        "ogrn": SS["OGRN"],
        "kpp": SS["KPP"],
        "idJwt": id_jwt,
    }
    jwt = create_jwt_via_api(header=header)
    resp = r.post(
        f"{SS['BASE_URL']}/api/token/confirm",
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
            query_data = get_info_from_query(id_jwt=id_jwt, queue=queue)
            confirm_data = confirm_of_getting_data(id_jwt=id_jwt)
            s = f"{id_jwt} -- {decode_base64_dict_to_utf8(query_data)} -- {confirm_data}"
            logger.info(s)
        return True
    else:
        print(f"{queue.capitalize()} queue is empty!")
        return False


def get_data_from_db(
    entity_type: str, skip: int = 0, limit: int = 20000, stage: int = None
) -> list:
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
            params={"skip": skip, "limit": limit, "stage": stage},
            headers={"Content-Type": "application/json"},
        )
        try:
            return resp.json()
        except:
            logger.error(resp.text)
            return None

    resp = r.get(
        f"{API_BASE_URL}{translator[entity_type]}",
        params={"skip": skip, "limit": limit},
        headers={"Content-Type": "application/json"},
    )
    try:
        return resp.json()
    except:
        logger.error(resp.text)
        return None


def get_document_from_epgu(user_guid: str, doc_uid_upgu: int) -> dict:
    """
    Получить доумент из заявления ЕПГУ
    """
    header = {
        "action": "get",
        "entityType": "document",
        "ogrn": SS["OGRN"],
        "kpp": SS["KPP"],
    }
    payload = f"""
    <PackageData>
        <Document>
            <IDEntrantChoice>
                <GUID>{user_guid}</GUID>
            </IDEntrantChoice>
            <IDDocChoice>
                <UIDEpgu>{doc_uid_upgu}</UIDEpgu>
            </IDDocChoice>
        </Document>
    </PackageData>
    """
    jwt = create_jwt_via_api(header=header, payload=payload)
    resp = r.post(
        f"{SS['BASE_URL']}/api/token/new",
        json={
            "token": jwt,
        },
        headers={"Content-Type": "application/json"},
    )
    time.sleep(3)
    try:
        data = decode_base64_dict_to_utf8(get_info_from_query(get_all_messages=False, queue='service', id_jwt=int(resp.json()["idJwt"])))
        return {
            'header': data['header'],
            'payload': ordereddict_to_dict(xmltodict.parse(data['payload']))["PackageData"] if data['payload'] else ''
        }
    except:
        logger.error(resp.text)
        return None


def get_identification_from_epgu(user_guid: str, identification_uid_upgu: int) -> dict:
    """
    Получить доумент из заявления ЕПГУ
    """
    header = {
        "action": "get",
        "entityType": "identification",
        "ogrn": SS["OGRN"],
        "kpp": SS["KPP"],
    }
    payload = f"""
    <PackageData>
        <Identification>
            <IDEntrantChoice>
                <GUID>{user_guid}</GUID>
            </IDEntrantChoice>
            <IDChoice>
                <UIDEpgu>{identification_uid_upgu}</UIDEpgu>
            </IDChoice>
        </Identification>
    </PackageData>
    """
    jwt = create_jwt_via_api(header=header, payload=payload)
    resp = r.post(
        f"{SS['BASE_URL']}/api/token/new",
        json={
            "token": jwt,
        },
        headers={"Content-Type": "application/json"},
    )
    time.sleep(3)
    try:
        data = decode_base64_dict_to_utf8(get_info_from_query(get_all_messages=False, queue='service', id_jwt=int(resp.json()["idJwt"])))
        return {
            'header': data['header'],
            'payload': ordereddict_to_dict(xmltodict.parse(data['payload']))["PackageData"] if data['payload'] else ''
        }
    except:
        logger.error(resp.text)
        return None


def edit_application_status_list(application_uid_upgu: int, id_status: int):
    """
    Изменить статус завяления ЕПГУ
    """
    header = {
        "action": "add",
        "entityType": "editApplicationStatusList",
        "ogrn": SS["OGRN"],
        "kpp": SS["KPP"],
    }
    payload = f"""
    <PackageData>
        <ApplicationStatus>
        <IDDocChoice>
        <UIDEpgu>{application_uid_upgu}</UIDEpgu>
        </IDDocChoice>
        <IDStatus>{id_status}</IDStatus>
        </ApplicationStatus>
    </PackageData>
    """
    jwt = create_jwt_via_api(header=header, payload=payload)
    resp = r.post(
        f"{SS['BASE_URL']}/api/token/new",
        json={
            "token": jwt,
        },
        headers={"Content-Type": "application/json"},
    )
    time.sleep(3)
    try:
        data = decode_base64_dict_to_utf8(get_info_from_query(get_all_messages=False, queue='service', id_jwt=int(resp.json()["idJwt"])))
        return {
            'header': data['header'],
            'payload': ordereddict_to_dict(xmltodict.parse(data['payload']))["PackageData"] if data['payload'] else ''
        }
    except:
        logger.error(resp.text)
        return None


def getter():
    """
    Job-а для получение idJwts из очереди ЕПГУ
    """
    queue = get_info_from_query(get_all_messages=True, queue="epgu")
    number_of_messages = queue.get("messages")
    if number_of_messages is not None:
        if int(number_of_messages) > 0:
            id_jwt_list = queue.get("idJwts")
            flag = False
            for el in id_jwt_list:
                j = session.query(Jwt).filter(Jwt.id_jwt_epgu == el).first()
                if not j:
                    session.add(Jwt(id_jwt_epgu=el))
                    flag = True
            if flag:
                session.add(
                    JwtJob(name="getter", status=1, query_dump=str(queue))
                )
            else:
                session.add(
                    JwtJob(name="getter", status=0, query_dump=str(queue))
                )
            session.commit()
        else:
            session.add(JwtJob(name="getter", status=0, query_dump=str(queue)))
            session.commit()
    else:
        session.add(JwtJob(name="getter", status=0, comment="Проблема с получением данных из очереди ЕПГУ! Возможно она недоступна."))
        session.commit()


def viewer():
    """
    Job-а для получения данных по idJwts, полученные getter()
    """
    jwt_list = session.query(Jwt).filter(Jwt.was_viewed == 0).all()
    if jwt_list:
        for jwt in jwt_list:
            data = get_info_from_query(
                get_all_messages=False, queue="epgu", id_jwt=jwt.id_jwt_epgu
            )
            data_decode = decode_base64_dict_to_utf8(data)
            if not data_decode:
                session.query(Jwt).filter(Jwt.id == jwt.id).update({Jwt.was_viewed: 1})
                session.add(
                    JwtJob(name="viewer", id_jwt=jwt.id, status=0, query_dump=str(data))
                )
                session.commit()
                raise ValueError("Полученно некорректное сообщение из очереди ЕГПУ!")
            datatypes = session.query(Datatype).all()
            datatypes_dict = dict(
                zip(
                    [datatype.name.lower() for datatype in datatypes],
                    [datatype.id for datatype in datatypes],
                )
            )
            entity_type = data_decode["header"].get("entityType")
            if entity_type:
                if entity_type.lower() in datatypes_dict.keys():
                    session.query(Jwt).filter(Jwt.id == jwt.id).update(
                        {
                            Jwt.id_datatype: datatypes_dict[entity_type.lower()],
                            Jwt.data: data_decode.get("payload"),
                            Jwt.was_viewed: 1
                        }
                    )
                    session.add(
                        JwtJob(
                            name="viewer", id_jwt=jwt.id, status=1, query_dump=str(data)
                        )
                    )
                    session.commit()
                else:
                    session.query(Jwt).filter(Jwt.id == jwt.id).update({Jwt.was_viewed: 1})
                    session.add(
                        JwtJob(
                            name="viewer", id_jwt=jwt.id, status=0, query_dump=str(data), comment="entity_type не соответсвтует datatypes"
                        )
                    )
                    session.commit()
            else:
                session.query(Jwt).filter(Jwt.id == jwt.id).update({Jwt.was_viewed: 1})
                session.add(
                    JwtJob(name="viewer", id_jwt=jwt.id, status=0, query_dump=str(data)), comment="entity_type отсутствует в header сообщения"
                )
                session.commit()
    else:
        session.add(
            JwtJob(name="viewer", status=0, comment="Нет новых данных для просмотра")
        )
        session.commit()


def jsonifier():
    """
    Job-а для конвретирования XML в JSON
    """
    jwt_list = session.query(
        Jwt
    ).filter(Jwt.was_viewed == 1, Jwt.was_jsonify == 0, Jwt.id_datatype != None).all()
    if jwt_list:
        for jwt in jwt_list:
            try:
                data_json = json.loads(
                    json.dumps(
                        xmltodict.parse(jwt.data),
                        ensure_ascii=False,
                        sort_keys=False
                    )
                )["PackageData"]
                user_guid = nested_lookup(
                    key='GUID',
                    document=data_json,
                    with_keys=False,
                    wild=False
                )[0]
                app_number = nested_lookup(
                    key='AppNumber',
                    document=data_json,
                    with_keys=False,
                    wild=False
                )[0]
                session.add(
                    JwtJson(
                        id_jwt=jwt.id,
                        status=1,
                        json=json.dumps(data_json, ensure_ascii=False, sort_keys=False)
                    )
                )
                session.add(
                    JwtJob(
                        name="jsonifier",
                        id_jwt=jwt.id,
                        status=1,
                        query_dump=json.dumps(data_json, ensure_ascii=False, sort_keys=False)
                    )
                )
            except:
                session.add(
                    JwtJson(id_jwt=jwt.id, status=0)
                )
                session.add(
                    JwtJob(name="jsonifier", id_jwt=jwt.id, status=0, query_dump=str(jwt.data))
                )
            session.query(Jwt).filter(Jwt.id == jwt.id).update(
                {Jwt.was_jsonify: 1, Jwt.user_guid: user_guid, Jwt.appnumber: app_number}
            )
            session.commit()
    else:
        session.add(
            JwtJob(name="jsonifier", status=0, comment="Нет новых данных")
        )
        session.commit()


def application_docs_finder(d: dict, tag: str) -> dict:
    """
    Поиск документов в заявлении ЕПГУ по тэгу
    """
    found_docs = nested_lookup(
        key=tag,
        document=d,
        with_keys=True,
        wild=False,
    )
    print(found_docs)
    clean_docs = {}
    if found_docs:
        for docs in found_docs[tag]:
            for key, value in docs.items():
                for k, v in value.items():
                    if isinstance(v, list):
                        lst = []
                        for el in v:
                            lst.extend(
                                nested_lookup(
                                    key='UIDEpgu',
                                    document=el,
                                    with_keys=False,
                                    wild=False
                                )
                            )
                        clean_docs[k.lower()] = lst
                    else:
                        clean_docs[k.lower()] = nested_lookup(
                            key='UIDEpgu',
                            document=v,
                            with_keys=False,
                            wild=False
                        )
    return clean_docs


def docifier():
    '''
    Job-а для получения документов из заявлений абитуриентов, в т.ч. паспорта
    '''
    jwt_list = session.query(Jwt).filter(Jwt.id_datatype == 1, Jwt.was_jsonify == 1, Jwt.was_docify == 0).all()
    jwt_json_list = session.query(
        JwtJson
    ).filter(JwtJson.id_jwt.in_([jwt.id for jwt in jwt_list]), JwtJson.json != None).all()
    if jwt_json_list:
        for jwt_json in jwt_json_list:
            flag = False
            json_data = json.loads(jwt_json.json)
            docs_search = nested_lookup(
                key='Documents',
                document=json_data,
                with_keys=True,
                wild=False,
            )
            uid_search = nested_lookup(
                key='UIDEpgu',
                document=docs_search,
                with_keys=False,
                wild=False,
            )
            docs = {'document': uid_search}
            user_guid = nested_lookup(
                key='GUID',
                document=json_data,
                with_keys=False,
                wild=False
            )
            if docs and user_guid:
                flag = True
                for k, v in docs.items():
                    for el in v:
                        doc = get_document_from_epgu(
                            user_guid=user_guid[0],
                            doc_uid_upgu=el
                        )
                        # TODO: если payload пустой ???
                        logger.warning(f"docifier -- document id_jwt -- {doc['header'].get('idJwt')}")
                        id_doctype = nested_lookup(
                            key='IDDocumentType',
                            document=doc['payload'],
                            with_keys=False,
                            wild=False
                        )
                        session.add(
                            JwtDoc(
                                id_jwt=jwt_json.id_jwt,
                                id_documenttype=int(id_doctype[0]),
                                data_json=json.dumps(doc['payload'], ensure_ascii=False, sort_keys=False),
                            )
                        )
                        session.commit()
            if flag:
                session.add(
                    JwtJob(name="docifier", id_jwt=jwt_json.id_jwt, status=1, query_dump=str(jwt_json.json))
                )
            else:
                session.add(
                    JwtJob(name="docifier", id_jwt=jwt_json.id_jwt, status=0, query_dump=str(jwt_json.json))
                )
            session.query(Jwt).filter(Jwt.id == jwt_json.id_jwt).update({Jwt.was_docify: 1})
            session.commit()
    else:
        session.add(
            JwtJob(name="docifier", status=0, comment="Нет новых данных")
        )
        session.commit()


def identifier():
    '''
    Job-а для получения документов, удостоверяющих личность
    '''
    jwt_list = session.query(
        Jwt
    ).filter(Jwt.id_datatype == 1, Jwt.was_jsonify == 1, Jwt.was_docify == 1, Jwt.was_identify == 0).all()
    jwt_json_list = session.query(
        JwtJson
    ).filter(JwtJson.id_jwt.in_([jwt.id for jwt in jwt_list]), JwtJson.json != None).all()
    if jwt_json_list:
        for jwt_json in jwt_json_list:
            flag = False
            json_data = json.loads(jwt_json.json)
            ident_search = nested_lookup(
                key='Identifications',
                document=json_data,
                with_keys=True,
                wild=False,
            )
            uid_search = nested_lookup(
                key='UIDEpgu',
                document=ident_search,
                with_keys=False,
                wild=False,
            )
            idents = {'identification': uid_search}
            user_guid = nested_lookup(
                key='GUID',
                document=json_data,
                with_keys=False,
                wild=False
            )
            if idents and user_guid:
                flag = True
                for k, v in idents.items():
                    for el in v:
                        ident_doc = get_identification_from_epgu(
                            user_guid=user_guid[0],
                            identification_uid_upgu=el
                        )
                        # TODO: если payload пустой ???
                        logger.warning(f"docifier -- document id_jwt -- {ident_doc['header'].get('idJwt')}")
                        id_doctype = nested_lookup(
                            key='IDDocumentType',
                            document=ident_doc['payload'],
                            with_keys=False,
                            wild=False
                        )
                        session.add(
                            JwtDoc(
                                id_jwt=jwt_json.id_jwt,
                                id_documenttype=int(id_doctype[0]),
                                data_json=json.dumps(ident_doc['payload'], ensure_ascii=False, sort_keys=False),
                            )
                        )
                        session.commit()
            if flag:
                session.add(
                    JwtJob(name="identifier", id_jwt=jwt_json.id_jwt, status=1, query_dump=str(jwt_json.json))
                )
            else:
                session.add(
                    JwtJob(name="identifier", id_jwt=jwt_json.id_jwt, status=0, query_dump=str(jwt_json.json))
                )
            session.query(Jwt).filter(Jwt.id == jwt_json.id_jwt).update({Jwt.was_identify: 1})
            session.commit()
    else:
        session.add(
            JwtJob(name="identifier", status=0, comment="Нет новых данных")
        )
        session.commit()


def uploader():
    """
    Job-а для выгрузки данных в БД ЦИУ (очередь ЕПГУ и связанные документы)
    """
    jwt_to_nstu_list = session.query(t_vw_jwt_to_nstu).filter(t_vw_jwt_to_nstu.c.was_uploaded == 0).all()
    if jwt_to_nstu_list:
        for jwt_to_nstu in jwt_to_nstu_list:
            resp = r.post(
                f"{API_BASE_URL}/api/db/insert-into-epgu-application",
                json={
                    "user_guid": jwt_to_nstu._asdict()['user_guid'],
                    "appnumber": jwt_to_nstu._asdict()['appnumber'],
                    "json_data": jwt_to_nstu._asdict()['json'],
                    "id_datatype": jwt_to_nstu._asdict()['id_datatype']
                },
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                session.query(Jwt).filter(Jwt.id == jwt_to_nstu._asdict()['id']).update({Jwt.was_uploaded: 1})
                session.add(
                    JwtJob(
                        name="uploader",
                        id_jwt=jwt_to_nstu._asdict()['id'],
                        status=1,
                        query_dump=json.dumps(jwt_to_nstu._asdict(), ensure_ascii=False, sort_keys=False)
                    )
                )
            else:
                session.add(
                    JwtJob(name="uploader", status=0, comment='jwt (проблема с вставкой)')
                )
            session.commit()
    else:
        session.add(
            JwtJob(name="uploader", status=0, comment='jwt')
        )
        session.commit()

    jwt_doc_to_nstu_list = session.query(
        t_vw_jwt_doc_to_nstu
    ).filter(
        t_vw_jwt_doc_to_nstu.c.was_uploaded == 0
    ).all()
    if jwt_doc_to_nstu_list:
        for jwt_doc_to_nstu in jwt_doc_to_nstu_list:
            resp = r.post(
                f"{API_BASE_URL}/api/db/insert-into-epgu-document",
                json={
                    "user_guid": jwt_doc_to_nstu._asdict()['user_guid'],
                    "appnumber": jwt_doc_to_nstu._asdict()['appnumber'],
                    "json_data": jwt_doc_to_nstu._asdict()['data_json'],
                    "id_documenttype": jwt_doc_to_nstu._asdict()['id_documenttype']
                },
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                session.query(JwtDoc).filter(JwtDoc.id == jwt_doc_to_nstu._asdict()['id']).update({JwtDoc.was_uploaded: 1})
                session.add(
                    JwtJob(
                        name="uploader",
                        id_jwt=jwt_doc_to_nstu._asdict()['id'],
                        status=1,
                        query_dump=json.dumps(jwt_doc_to_nstu._asdict(), ensure_ascii=False, sort_keys=False)
                    )
                )
            else:
                session.add(
                    JwtJob(name="uploader", status=0, comment='docs (проблема с вставкой)')
                )
            session.commit()
    else:
        session.add(
            JwtJob(name="uploader", status=0, comment='docs')
        )
        session.commit()


def status_syncer():
    """
    Job-а для синхронизации статусов ЕПГУ
    """
    resp_ciu = r.get(
        f"{API_BASE_URL}/api/db/get-statuses-to",
        params={"skip": 0, "limit": 5000},
        headers={"Content-Type": "application/json"},
    )
    resp_json = resp_ciu.json()
    if resp_json:
        for status in resp_json:
            jwt = session.query(
                t_vw_jwt_to_nstu
            ).filter(
                t_vw_jwt_to_nstu.c.appnumber == status['epgu_application_id'],
                t_vw_jwt_to_nstu.c.id_datatype == 1
            ).first()
            resp_status = edit_application_status_list(
                application_uid_upgu=jwt._asdict()['appnumber'],
                id_status=status['id_ss_applicationstatuses']
            )
            if resp_status:
                if resp_status["header"].get("payloadType") == "success":
                    session.query(
                        Jwt
                    ).filter(
                        Jwt.appnumber == status['epgu_application_id']
                    ).update(
                        {
                            Jwt.current_status: status['id_ss_applicationstatuses'],
                        }
                    )
                    session.add(
                        JwtJob(
                            name="status_syncer",
                            id_jwt=jwt._asdict()['id'],
                            status=1,
                            query_dump=json.dumps(resp_status, ensure_ascii=False, sort_keys=False)
                        )
                    )
                    resp = r.post(
                        f"{API_BASE_URL}/api/db/update-statuses-to",
                        json={
                            "pk": status['pk'],
                            "is_processed": 1,
                            "err_msg": '-'
                        },
                        headers={"Content-Type": "application/json"},
                    )
                else:
                    session.add(
                        JwtJob(
                            name="status_syncer",
                            id_jwt=jwt._asdict()['id'],
                            status=0,
                            query_dump=json.dumps(resp_status, ensure_ascii=False, sort_keys=False)
                        )
                    )
                    resp = r.post(
                        f"{API_BASE_URL}/api/db/update-statuses-to",
                        json={
                            "pk": status['pk'],
                            "is_processed": 1,
                            "err_msg": json.dumps(resp_status, ensure_ascii=False, sort_keys=False)
                        },
                        headers={"Content-Type": "application/json"},
                    )
            else:
                session.add(
                    JwtJob(name="status_syncer", status=0, comment='(очередь недоступна)')
                )
                resp = r.post(
                    f"{API_BASE_URL}/api/db/update-statuses-to",
                    json={
                        "pk": status['pk'],
                        "is_processed": 1,
                        "err_msg": '(очередь недоступна)'
                    },
                    headers={"Content-Type": "application/json"},
                )
        session.commit()
    else:
        session.add(
            JwtJob(name="status_syncer", status=0)
        )
        session.commit()


if __name__ == "__main__":
    # ? получить справочник по его имени
    # data = get_sprav_by_name(name='ApplicationStatuses')
    # data_decode = decode_str_to_utf8(data)
    # print(data_decode)

    # ? получить экземпляр сущности
    # print(
    #     entity(
    #         action="get",
    #         entity_type="termsAdmission",
    #         record={"UID": 2899244205},
    #     )
    # )

    # ? получение данных из очереди СС
    # print(decode_base64_dict_to_utf8(get_info_from_query(get_all_messages=False, queue='service', id_jwt=1137106)))

    # ? получение данных из очереди ЕПГУ
    # print(get_info_from_query(get_all_messages=True, queue='epgu'))

    # ? выгрузка данных из БД в СС
    # d = get_data_from_db(entity_type='entranceTest', stage=3)
    # for el in d:
    #     print(el)
    #     print(entity(action="add", entity_type="entranceTest", record=el))

    # ? подтвердить получение из очереди всех данных
    # confirm_all()

    # ? получить документ из ЕПГУ
    # print(
    #     get_document_from_epgu(
    #         user_guid='7a7bf3b5-f6ae-4a20-bfe7-94728c3d7778',
    #         doc_uid_upgu=54160
    #     )
    # )

    # ? получить документ, удостоверящий личность из ЕПГУ
    # print(
    #     get_identification_from_epgu(
    #         user_guid='7a7bf3b5-f6ae-4a20-bfe7-94728c3d7778',
    #         identification_uid_upgu=26505
    #     )
    # )

    # ? Изменить статус заялвения на ЕПГУ
    # print(edit_application_status_list(application_uid_upgu=12556058911, id_status=2))

    # ? job-а для получения очереди ЕГПУ
    getter()

    # ? job-а для получения данных по id из очереди ЕГПУ
    # viewer()

    # ? job-а для конвертирования полученных данных из XML в JSON
    # jsonifier()

    # ? job-а для полученния документов из заявления
    # docifier()

    # ? job-а для получения документа, удостоверяющего личность, из заявления
    # identifier()

    # ?  job-а для получения документа, удостоверяющего личность, из заявления
    # uploader()

    # ? job-а для синхронизации статусов ЕПГУ с БД ЦИУ
    # status_syncer()
