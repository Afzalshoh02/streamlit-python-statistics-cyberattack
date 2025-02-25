# app/filters.py
def apply_filters(df, severity_filter, attack_type_filter, year_filter, packet_length_filter):
    """
    Применяет фильтры к DataFrame:
      - Фильтр по уровню угрозы
      - Фильтр по типу атаки
      - Фильтр по году (на основе столбца Timestamp)
      - Фильтр по диапазону длины пакета
    """
    filtered_df = df[
        (df['Severity Level'].isin(severity_filter)) &
        (df['Attack Type'].isin(attack_type_filter)) &
        (df['Timestamp'].dt.year.between(year_filter[0], year_filter[1])) &
        (df['Packet Length'].between(packet_length_filter[0], packet_length_filter[1]))
    ]
    return filtered_df
