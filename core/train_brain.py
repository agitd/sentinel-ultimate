import pandas as pd
from sklearn.ensemble import RandomForestRegressor
import joblib
import os

def train_my_model():
    print("[*] Начинаю обучение Tiny-Sentinel...")

    # Пути к файлам
    csv_path = os.path.join('ai_data', 'cve_data.csv')
    model_path = os.path.join('core', 'sentinel_model.pkl')

    if not os.path.exists(csv_path):
        print(f"[-] Ошибка: Файл {csv_path} не найден!")
        return

    # Загружаем данные
    data = pd.read_csv(csv_path)
    X = data[['port']] # Вход: номера портов
    y = data['risk_score'] # Выход: уровень риска

    # Создание и обучение модели (Случайный лес)
    model = RandomForestRegressor(n_estimators=100, random_state=42)
    model.fit(X, y)

    # Сохранение результата
    joblib.dump(model, model_path)
    print(f"[+] Обучение завершено. Модель сохранена в {model_path}")

if __name__ == "__main__":
    train()

