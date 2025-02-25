import plotly.express as px
import seaborn as sns
import matplotlib.pyplot as plt


def plot_scatter(df):
    """
    Создает scatter-графики:
      1. Packet Length Over Time
      2. Source vs Destination Port
      3. Severity Level vs Packet Length
    """
    fig1 = px.scatter(df, x='Timestamp', y='Packet Length', title='Packet Length Over Time')
    fig2 = px.scatter(df, x='Source Port', y='Destination Port', title='Source vs Destination Port')
    fig3 = px.scatter(df, x='Severity Level', y='Packet Length', title='Severity Level vs Packet Length')
    return fig1, fig2, fig3


def plot_histogram_bar(df):
    """
    Создает histogram и bar chart для распределения длины пакета.
    """
    fig4 = px.histogram(df, x='Packet Length', title='Packet Length Distribution', nbins=30, color='Severity Level', barmode='overlay')
    df_grouped = df.groupby('Severity Level')['Packet Length'].mean().reset_index()
    fig5 = px.bar(df_grouped, x='Severity Level', y='Packet Length', title='Average Packet Length per Severity Level', color='Severity Level')
    return fig4, fig5


def plot_line(df):
    """
    Создает линейный график изменения длины пакета по времени с раскраской по уровню угрозы.
    """
    fig6 = px.line(df, x='Timestamp', y='Packet Length', color='Severity Level', title='Packet Length Over Time by Severity Level')
    return fig6


# Плотность: Anomaly Scores
def plot_density(df):
    """График плотности аномальных баллов"""
    fig7, ax = plt.subplots(figsize=(10, 6))
    sns.kdeplot(df['Anomaly Scores'], ax=ax, fill=True, color='blue')
    ax.set_title("Density Plot of Anomaly Scores")
    return fig7


# Тепловая карта: Attack Type vs Severity Level
def plot_heatmap(df):
    """Тепловая карта типа атаки против уровня угрозы"""
    heatmap_data = df.groupby(['Attack Type', 'Severity Level']).size().unstack(fill_value=0)
    fig8, ax = plt.subplots(figsize=(10, 6))
    sns.heatmap(heatmap_data, annot=True, cmap="YlGnBu", ax=ax)
    ax.set_title("Attack Type vs Severity Level")
    return fig8

