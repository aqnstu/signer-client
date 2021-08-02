# coding: utf-8
import base64
from datetime import datetime
import jinja2
import json
import os
import time

from db import session
from log import logger
from models import ApplicationList
from utils import (
    get_data_from_db,
    lower_dict_keys,
    get_info_from_query,
    decode_base64_dict_to_utf8,
    modify_data,
)


def to_base64_string(s: str) -> str:
    """Конвертировать строку в строку BASE64"""
    return base64.b64encode(s.encode("utf-8")).decode("utf-8")


def get_competitive_group_applications_list_by_uid(uid: int) -> str:
    """Получить конкурсный список по UID конкурсной группы"""
    with open(
        os.path.join(
            "schemas",
            "payload",
            "competitiveGroupApplicationsList",
            "template_application.xml",
        )
    ) as f:
        template = f.read()

    app_lists = get_data_from_db(
        entity_type="competitiveGroupApplicationsList",
        skip=0,
        limit=20000,
        stage=None,
        competitive_group=uid,
    )
    print(len(app_lists))

    app_lists_xml = []
    for i, record in enumerate(app_lists):
        record_lower = lower_dict_keys(record)
        if i == 0:
            head_xml = (
                "<PackageData><CompetitiveGroupApplicationsList>"
                f"<UIDCompetitiveGroup>{record_lower['uidcompetitivegroup']}</UIDCompetitiveGroup>"
                f"<AdmissionVolume>{record_lower['admissionvolume']}</AdmissionVolume>"
                f"<CountFirstStep>{record_lower['countfirststep']}</CountFirstStep>"
                f"<CountSecondStep>{record_lower['countsecondstep']}</CountSecondStep>"
                f"<Changed>{record_lower['changed'] + '+07:00'}</Changed>"
                "<Applications>"
            )
            end_xml = "</Applications></CompetitiveGroupApplicationsList></PackageData>"
        template_data = jinja2.Template(template)
        app_lists_xml.append(template_data.render(**record_lower))

    payload = str.join("", app_lists_xml)

    return head_xml + payload + end_xml


def get_competitive_group_applications_list_package(
    uid: str, name: str, base64file: str
) -> str:
    """Получить пакет с конкурсным списком для отправки в СС"""
    with open(
        os.path.join(
            "schemas",
            "payload",
            "competitiveGroupApplicationsList",
            "template_package.xml",
        )
    ) as f:
        template = f.read()

    template_data = jinja2.Template(template)
    payload = template_data.render(uid=uid, name=name, base64file=base64file)

    return payload


def upload_competitive_group_applications_lists():
    """Выгрузить конкурсные списки в СС"""
    current_timestamp = datetime.now().replace(microsecond=0).isoformat()
    competitive_groups = get_data_from_db(entity_type="competitiveGroup")
    for competitive_group in competitive_groups:
        app_list = get_competitive_group_applications_list_by_uid(
            competitive_group["UID"]
        )
        app_list_base64 = to_base64_string(app_list)
        app_list_package = get_competitive_group_applications_list_package(
            uid=f"{competitive_group['UID']}_{current_timestamp}",
            name=f"{competitive_group['Comment'][0:8]}_{competitive_group['fk_competition']}_{current_timestamp}",
            base64file=app_list_base64,
        )

        id_jwt = modify_data(
            action="add",
            entity_type="competitiveGroupApplicationsList",
            payload=app_list_package,
        )

        session.add(
            ApplicationList(
                uid_competitive_group=competitive_group["UID"],
                name=f"{competitive_group['Comment'][0:8]}_{competitive_group['fk_competition']}_{current_timestamp}",
                base64file=app_list_base64,
                fk_competition=competitive_group["fk_competition"],
                id_jwt_message=int(id_jwt),
            )
        )
        session.commit()


def get_message_for_competitive_group_applications_lists():
    """Получить сообщения из очереди ЕПГУ о результате операции"""
    records = (
        session.query(ApplicationList).filter(ApplicationList.was_viewed == 0).all()
    )
    for record in records:
        flag = True
        iters = 0
        while flag:
            data = decode_base64_dict_to_utf8(
                get_info_from_query(
                    get_all_messages=False,
                    queue="service",
                    id_jwt=record.id_jwt_message,
                )
            )
            if data:
                flag = False
            else:
                iters += 1
                if iters == 1:
                    logger.error(
                        f"lists: {record.id} - {record.uid_competitive_group} - {record.id_jwt_message} - Данные еще не поступили в очередь или очередь недоступна"
                    )
                time.sleep(0.5)

        session.query(ApplicationList).filter(ApplicationList.id == record.id).update(
            {
                ApplicationList.was_viewed: 1,
                ApplicationList.message: json.dumps(
                    data, ensure_ascii=False, sort_keys=False
                ),
            }
        )
        session.commit()


if __name__ == "__main__":
    upload_competitive_group_applications_lists()
    time.sleep(3)
    get_message_for_competitive_group_applications_lists()
