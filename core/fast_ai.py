import joblib
import numpy as np
import os

# Путь к обученным мозгам
MODEL_PATH = os.path.join('core', 'sentinel_model.pkl')

def get_risk_score(ports_list):
    """
    Принимает список портов, например ['22', '80', '445'].
    Возвращает максимальный риск от 0 до 1.
    """
    try:
        # Загружаем модель
        model = joblib.load(MODEL_PATH)

        # Если портов нет - риск нулевой
        if not ports_list:
            return 0.0

        # Преобразует порты в числа для нейронки
        numeric_ports = []
        for p in ports_list:
            try:
                numeric_ports.append([int(p)])
            except:
                continue

        if not numeric_ports:
            return 0.0

        # Нейронка предсказывает риск для каждого порта
        predictions = model.predict(numeric_ports)

        # Берет самый высокий риск из найденных
        return float(np.max(predictions))

    except Exception as e:
        print(f"[!] Ошибка работы Tiny-Sentinel: {e}")
        return 0.5 # В случае ошибки считает риск средним
