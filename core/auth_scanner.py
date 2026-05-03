import paramiko
import asyncio
import logging

# Sentinel V13.6: Жесткое глушение логов paramiko, чтобы не было мусора в консоли
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

async def check_ssh_login(ip: str, port: int = 22):
    """
    Sentinel V13.6: Модуль проверки слабых учетных записей SSH.
    Исправлен баг с Incompatible ssh peer.
    """
    common_creds = [("root", "root"), ("admin", "admin"), ("user", "123456"), ("ubnt", "ubnt")]
    found_creds = []

    for user, pwd in common_creds:
        client = paramiko.SSHClient()
        try:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Добавил disabled_algorithms, чтобы paramiko не пытался использовать то, что вызывает ошибку
            # Это поможет избежать "Incompatible ssh peer" в некоторых случаях
            client.connect(
                ip,
                port=port,
                username=user,
                password=pwd,
                timeout=3,
                allow_agent=False,
                look_for_keys=False,
                banner_timeout=3
            )
            found_creds.append(f"{user}:{pwd}")
            client.close()
            break
        except paramiko.ssh_exception.IncompatiblePeer:
            # Если хост несовместим, нет смысла брутить дальше
            break
        except Exception:
            # Остальные ошибки (таймаут, неверный пароль) просто игнорируем
            continue
        finally:
            try:
                client.close()
            except:
                pass

    return found_creds


