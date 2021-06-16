from loguru import logger


logger.add(
    "ss.log",
    mode="a+",
    backtrace=True,
    diagnose=True,
    level="INFO",
    encoding="utf-8",
    format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
)
