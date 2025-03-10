# Streamlit Cybersecurity Data Analysis

## Описание

Проект для анализа данных атак в кибербезопасности с использованием **Streamlit**. Включает фильтрацию данных и визуализацию информации о типах атак, уровне опасности, протоколах, местоположении и других показателях. Также реализована система регистрации и входа с использованием логина и пароля, где пароли хешируются и сохраняются в базе данных MySQL.

## Установка

1. Установите зависимости:
    ```bash
    pip install -r requirements.txt
    ```

2. Запустите приложение:
    ```bash
    streamlit run main.py
    ```

## Функционал

- **Фильтрация данных** по различным критериям (типы атак, протоколы, уровень опасности и т.д.)
- **Визуализация данных**:
    - Гистограммы
    - Графики
    - Плотности
    - Тепловые карты
- **Система регистрации и входа**:
    - Регистрация пользователей с логином и паролем
    - Хеширование паролей для безопасности
    - Сохранение учетных данных в базе данных MySQL
- **Используемые библиотеки**:
    - `pandas` для обработки данных
    - `plotly.express` для визуализаций
    - `seaborn` для создания статистических графиков
    - `matplotlib` для построения графиков
    - `sklearn.preprocessing.LabelEncoder` для кодирования категориальных данных
    - `mysql-connector-python` для работы с MySQL
