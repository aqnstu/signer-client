select
    1305781877 "UIDCampaign",
    ora_hash(name) "UID",
    name,
    id
from
    (
        select
            tam.id,
            tak.NAME || ' (' || lower(el.name) || ', ' || lower(ef.name) || ', ' || lower(es.name) || ')' name,
            tam.IDTERMSADMISSION,
            tam.IDEDUCATIONLEVEl,
            tam.IDEDUCATIONFORM,
            tam.IDEDUCATIONSOURCE
        from
            SS_TERMSADMISSIONMATCHES tam
            join SS_TERMSADMISSIONKINDS tak on tam.IDTERMSADMISSION = tak.id
            join SS_EDUCATIONLEVELS el on tam.IDEDUCATIONLEVEL = el.ID
            join SS_EDUCATIONFORMS ef on tam.IDEDUCATIONFORM = ef.ID
            join SS_EDUCATIONSOURCES es on tam.IDEDUCATIONSOURCE = es.id
        where
            (
                tam.IDTERMSADMISSION = 1
                or tam.IDTERMSADMISSION = 4
                or tam.IDTERMSADMISSION = 10
            )
            and (
                tam.IDEDUCATIONLEVEL = 2
                or tam.IDEDUCATIONLEVEL = 3
            )
            and (
                tam.IDEDUCATIONFORM = 1
                or tam.IDEDUCATIONFORM = 2
            )
            and (tam.IDEDUCATIONSOURCE = 1)
        union
        all
        select
            tam.id,
            tak.NAME || ' (' || lower(el.name) || ', ' || lower(ef.name) || ', ' || lower(es.name) || ')' name,
            IDTERMSADMISSION,
            tam.IDEDUCATIONLEVEl,
            tam.IDEDUCATIONFORM,
            tam.IDEDUCATIONSOURCE
        from
            SS_TERMSADMISSIONMATCHES tam
            join SS_TERMSADMISSIONKINDS tak on tam.IDTERMSADMISSION = tak.id
            join SS_EDUCATIONLEVELS el on tam.IDEDUCATIONLEVEL = el.ID
            join SS_EDUCATIONFORMS ef on tam.IDEDUCATIONFORM = ef.ID
            join SS_EDUCATIONSOURCES es on tam.IDEDUCATIONSOURCE = es.id
        where
            (
                tam.IDTERMSADMISSION = 1
                or tam.IDTERMSADMISSION = 4
                or tam.IDTERMSADMISSION = 9
            )
            and (
                tam.IDEDUCATIONLEVEL = 2
                or tam.IDEDUCATIONLEVEL = 3
            )
            and (
                tam.IDEDUCATIONFORM = 1
                or tam.IDEDUCATIONFORM = 2
            )
            and (tam.IDEDUCATIONSOURCE = 4)
    ) t
order by
    t.IDTERMSADMISSION,
    t.IDEDUCATIONLEVEL,
    t.IDEDUCATIONFORM