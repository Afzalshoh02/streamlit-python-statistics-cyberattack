# main.py
import streamlit as st
import pandas as pd
import plotly.express as px
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder

from app.auth import check_credentials, register_user
from app.database import get_db_connection
from app.filters import apply_filters
from app.plots import plot_scatter, plot_histogram_bar, plot_line, plot_density, plot_heatmap

st.title("📊 Cybersecurity Attacks Dashboard")

# Инициализация сессионной переменной для авторизации
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

if st.session_state.logged_in:
    # Отображаем кнопку для логаута
    if st.button('Logout'):
        st.session_state.logged_in = False
        st.success("Вы успешно вышли из системы.")
        
        
# Если пользователь не авторизован – показываем форму регистрации/входа
if not st.session_state.logged_in:
    option = st.selectbox("Выберите действие", ["Регистрация", "Вход"])
    
    if option == "Регистрация":
        st.subheader("📋 Регистрация")
        username = st.text_input("Введите ваш email")
        password = st.text_input("Введите пароль", type="password")
        confirm_password = st.text_input("Подтвердите пароль", type="password")
        if st.button("Зарегистрироваться"):
            if password == confirm_password:
                if register_user(username, password):
                    st.success("Регистрация прошла успешно! Пожалуйста, войдите в систему.")
                else:
                    st.error("Пользователь с таким email уже существует или произошла ошибка.")
            else:
                st.error("Пароли не совпадают. Попробуйте снова.")
    
    elif option == "Вход":
        st.subheader("🔑 Вход в систему")
        username = st.text_input("Введите ваш email")
        password = st.text_input("Введите пароль", type="password")
        if st.button("Войти"):
            if check_credentials(username, password):
                st.session_state.logged_in = True
                st.success("Вход выполнен успешно!")
            else:
                st.error("Неверный email или пароль")

# Если пользователь авторизован – показываем основной контент
else:
    st.sidebar.header("Filters")
    file_path = r"cybersecurity_attacks.csv"
    df = pd.read_csv(file_path)
    
    # Преобразуем столбец Timestamp в datetime
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    if df['Timestamp'].isnull().any():
        st.warning("Обнаружены недопустимые или отсутствующие значения времени.")
    
    # Применяем LabelEncoder для Severity Level (если требуется)
    label_encoder = LabelEncoder()
    df['Severity Level Encoded'] = label_encoder.fit_transform(df['Severity Level'])
    
    # Фильтры в боковой панели
    # severity_filter = st.sidebar.multiselect("Select Severity Level(s)", df['Severity Level'].unique(), default=list(df['Severity Level'].unique()))
    # attack_type_filter = st.sidebar.multiselect("Select Attack Type(s)", df['Attack Type'].unique(), default=list(df['Attack Type'].unique()))
    # year_filter = st.sidebar.slider("Select Year", min_value=int(df['Timestamp'].dt.year.min()),
    #                                 max_value=int(df['Timestamp'].dt.year.max()),
    #                                 value=(int(df['Timestamp'].dt.year.min()), int(df['Timestamp'].dt.year.max())))
    # packet_length_filter = st.sidebar.slider("Select Packet Length Range", min_value=int(df['Packet Length'].min()),
    #                                            max_value=int(df['Packet Length'].max()),
    #                                            value=(int(df['Packet Length'].min()), int(df['Packet Length'].max())))
    
    severity_filter = st.sidebar.multiselect("Select Severity Level(s)", df['Severity Level'].unique(), default=list(df['Severity Level'].unique()))
    attack_type_filter = st.sidebar.multiselect("Select Attack Type(s)", df['Attack Type'].unique(), default=list(df['Attack Type'].unique()))
    year_filter = st.sidebar.slider("Select Year", int(df['Timestamp'].dt.year.min()), int(df['Timestamp'].dt.year.max()), (int(df['Timestamp'].dt.year.min()), int(df['Timestamp'].dt.year.max())))
    packet_length_filter = st.sidebar.slider("Select Packet Length Range", int(df['Packet Length'].min()), int(df['Packet Length'].max()), (int(df['Packet Length'].min()), int(df['Packet Length'].max())))
    
    
    # Применяем фильтры к данным
    filtered_df = apply_filters(df, severity_filter, attack_type_filter, year_filter, packet_length_filter)
    
    # Создаем вкладки для визуализаций
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "Scatter Plots", 
        "Histogram & Bar Chart", 
        "Line Chart", 
        "Advanced Analysis", 
        "Pie Charts", 
        "Attack Overview"
    ])
    
    # Вкладка 1: Scatter Plots
    with tab1:
        st.subheader("📌 Scatter Plots")
        fig1, fig2, fig3 = plot_scatter(filtered_df)
        st.plotly_chart(fig1)
        st.plotly_chart(fig2)
        st.plotly_chart(fig3)
        st.subheader("Advanced Analysis")
        fig7 = plot_density(filtered_df)
        st.pyplot(fig7)
        
        fig8 = plot_heatmap(filtered_df)
        st.pyplot(fig8)
    
    # Вкладка 2: Histogram & Bar Chart
    with tab2:
        st.subheader("📊 Histogram & Bar Chart")
        fig4, fig5 = plot_histogram_bar(filtered_df)
        st.plotly_chart(fig4)
        st.plotly_chart(fig5)
    
    # Вкладка 3: Line Chart
    with tab3:
        st.subheader("📈 Line Chart")
        fig6 = plot_line(filtered_df)
        st.plotly_chart(fig6)
    
    # Вкладка 4: Advanced Analysis
    with tab4:
        st.subheader("🔍 Advanced Analysis")
        high_severity = filtered_df[
            (filtered_df['Severity Level'].str.contains('High', case=False, na=False)) &
            (filtered_df['Attack Type'] == 'DDoS')
        ]
        high_severity = high_severity.sort_values(by='Timestamp', ascending=True)
        st.write(high_severity[['Timestamp', 'Severity Level', 'Attack Type', 'Source IP Address', 'Destination IP Address']].head(10))
        
        st.subheader("🔢 Anomaly Scores Distribution")
        fig, ax = plt.subplots(figsize=(10, 6))
        sns.histplot(filtered_df['Anomaly Scores'], bins=30, kde=True, ax=ax)
        ax.set_title("Histogram of Anomaly Scores")
        st.pyplot(fig)
        
        filtered_df['Year'] = filtered_df['Timestamp'].dt.year
        fig, ax = plt.subplots(figsize=(10, 6))
        sns.boxplot(x=filtered_df['Year'], y=filtered_df['Anomaly Scores'], ax=ax)
        ax.set_title("Boxplot of Anomaly Scores by Year")
        st.pyplot(fig)
    
    # Вкладка 5: Pie Charts
    with tab5:
        st.subheader("🎯 Pie Charts")
        st.subheader("Distribution of Severity Levels")
        fig, ax = plt.subplots(figsize=(8, 5))
        filtered_df['Severity Level'].value_counts().plot(kind='pie', autopct='%1.1f%%', colors=sns.color_palette("pastel"), startangle=90, ax=ax)
        ax.set_ylabel("")
        st.pyplot(fig)
        
        st.subheader("Pie Chart of Action Taken")
        fig, ax = plt.subplots(figsize=(8, 8))
        filtered_df['Action Taken'].value_counts().plot.pie(autopct='%1.1f%%', startangle=90, ax=ax)
        ax.set_ylabel("")
        st.pyplot(fig)
    
    # Вкладка 6: Attack Overview
    with tab6:
        # st.subheader("📊 Attack Overview: Severity vs Packet Length (Animated)")
        # attack_types = ['DDoS', 'Phishing', 'Malware', 'SQL Injection', 'Brute Force', 'MITM', 'DoS']
        # attack_filter = st.sidebar.multiselect("Select Attack Type(s)", attack_types, default=attack_types)
        # filtered_attack_df = filtered_df[filtered_df['Attack Type'].isin(attack_filter)]
        
        # if filtered_attack_df.empty:
        #     st.warning("No data available for the selected attack types. Please try selecting different types.")
        
        # fig_attack_overview = px.scatter(
        #     filtered_attack_df,
        #     x='Packet Length',
        #     y='Severity Level',
        #     size='Anomaly Scores',
        #     color='Attack Type',
        #     animation_frame="Timestamp",
        #     animation_group="Attack Type",
        #     log_x=True,
        #     size_max=60,
        #     title="Severity vs Packet Length Over Time (Animated)",
        #     category_orders={"Attack Type": attack_types}
        # )
        # st.plotly_chart(fig_attack_overview)
        

        # Select Attack Types
        # Выбор типов атак
        attack_types = ['DDoS', 'Phishing', 'Malware', 'SQL Injection', 'Brute Force', 'MITM', 'DoS']
        selected_attacks = st.sidebar.multiselect(
            "Select Attack Type(s):", 
            attack_types, 
            default=attack_types,
            key="attack_types_multiselect"  # Уникальный ключ
        )

        # Если ничего не выбрано, используем все типы атак
        if not selected_attacks:
            selected_attacks = attack_types

        # Фильтр уровней серьезности
        severity_levels = filtered_df['Severity Level'].unique().tolist()
        selected_severity = st.sidebar.multiselect(
            "Select Severity Level(s):", 
            severity_levels, 
            default=severity_levels,
            key="severity_levels_multiselect"  # Уникальный ключ
        )

        # Если ничего не выбрано, используем все уровни серьезности
        if not selected_severity:
            selected_severity = severity_levels

        # Фильтр диапазона времени (исправление для Timestamp)
        time_min = filtered_df['Timestamp'].min().to_pydatetime()
        time_max = filtered_df['Timestamp'].max().to_pydatetime()
        time_range = st.sidebar.slider(
            "Select Time Range:", 
            min_value=time_min, 
            max_value=time_max, 
            value=(time_min, time_max),
            key="time_range_slider"  # Уникальный ключ
        )

        # Фильтрация данных
        filtered_attack_df = filtered_df[(filtered_df['Attack Type'].isin(selected_attacks)) & 
                                        (filtered_df['Severity Level'].isin(selected_severity)) &
                                        (filtered_df['Timestamp'].between(pd.Timestamp(time_range[0]), pd.Timestamp(time_range[1])))]

        # Scatter Plot: Severity vs Packet Length (Animated)
        st.subheader("📊 Attack Overview: Severity vs Packet Length (Animated)")
        if filtered_attack_df.empty:
            st.warning("No data available for the selected filters. Please adjust your filters.")
        else:
            fig_attack_overview = px.scatter(
                filtered_attack_df, 
                x='Packet Length', 
                y='Severity Level', 
                size='Anomaly Scores', 
                color='Attack Type', 
                animation_frame="Timestamp", 
                animation_group="Attack Type",
                log_x=True, 
                size_max=60, 
                title="Severity vs Packet Length Over Time (Animated)")
            st.plotly_chart(fig_attack_overview)

        # Гистограмма: Распределение уровней серьезности
        st.subheader("📈 Severity Level Distribution")
        if filtered_attack_df.empty:
            st.warning("No data available for the selected filters.")
        else:
            fig_severity_dist = px.histogram(filtered_attack_df, x="Severity Level", nbins=30, color="Attack Type", barmode="overlay")
            st.plotly_chart(fig_severity_dist)

        # Bar Chart: Топ-10 атак по аномальным показателям (последний временной метке в диапазоне)
        st.subheader("💰 Top 10 Attacks by Anomaly Score")
        if filtered_attack_df.empty:
            st.warning("No data available for the selected filters.")
        else:
            latest_timestamp = filtered_attack_df["Timestamp"].max()
            top_attacks = filtered_attack_df[filtered_attack_df["Timestamp"] == latest_timestamp].nlargest(10, "Anomaly Scores")
            fig_top_attacks = px.bar(top_attacks, x="Attack Type", y="Anomaly Scores", color="Severity Level", title=f"Top 10 Attacks by Anomaly Score ({latest_timestamp})")
            st.plotly_chart(fig_top_attacks)

        # Линейный график: Тренд аномальных показателей
        st.subheader("📊 Anomaly Score Trends Over Time")
        if filtered_attack_df.empty:
            st.warning("No data available for the selected filters.")
        else:
            fig_anomaly_trend = px.line(filtered_attack_df, x="Timestamp", y="Anomaly Scores", color="Attack Type", title="Anomaly Scores Over Time")
            st.plotly_chart(fig_anomaly_trend)

        # Отображение отфильтрованной таблицы данных
        if st.checkbox("Show Filtered Data Table"):
            st.write(filtered_attack_df)
        
        # st.subheader("📈 Attack Severity Distribution by Attack Type")
        # fig2 = px.histogram(
        #     filtered_attack_df,
        #     x="Packet Length",
        #     nbins=30,
        #     color="Severity Level",
        #     barmode="overlay",
        #     title="Packet Length Distribution by Severity Level"
        # )
        # st.plotly_chart(fig2)
        
        # st.subheader("💣 Top Attack Types by Severity Level")
        # latest_year = filtered_attack_df["Timestamp"].max()
        # top_attack_types = filtered_attack_df[filtered_attack_df["Timestamp"] == latest_year].groupby('Attack Type').agg({
        #     'Packet Length': 'mean',
        #     'Severity Level': 'first'
        # }).reset_index()
        # fig3 = px.bar(
        #     top_attack_types,
        #     x="Attack Type",
        #     y="Packet Length",
        #     color="Severity Level",
        #     title=f"Top Attack Types by Packet Length (Severity Level) in {latest_year}",
        #     category_orders={"Attack Type": attack_types}
        # )
        # st.plotly_chart(fig3)
        
        # st.subheader("📊 Attack Trends Over Time by Attack Type")
        # fig4 = px.line(
        #     filtered_attack_df,
        #     x="Timestamp",
        #     y="Packet Length",
        #     color="Attack Type",
        #     title="Packet Length Over Time by Attack Type"
        # )
        # st.plotly_chart(fig4)
        
        if st.checkbox("Show Data Table"):
            st.write(filtered_attack_df)
    