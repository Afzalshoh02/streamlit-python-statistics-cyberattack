import pandas as pd
import plotly.express as px
import matplotlib.pyplot as plt
import streamlit as st

def plot_packet_length(df):
    """График изменения длины пакетов"""
    fig = px.scatter(df, x='Timestamp', y='Packet Length', title='Packet Length Over Time')
    return fig


def plot_severity_distribution(df):
    """График распределения по уровням угроз"""
    fig = px.histogram(df, x='Severity Level', title='Severity Level Distribution')
    return fig


