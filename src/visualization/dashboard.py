import dash
from dash import dcc, html, Input, Output
import plotly.graph_objs as go
import pandas as pd
from datetime import datetime
import threading
import json

class Dashboard:
    def __init__(self, correlation_engine):
        self.correlation_engine = correlation_engine
        self.app = dash.Dash(__name__)
        self.setup_layout()
        self.setup_callbacks()
        
    def setup_layout(self):
        """Setup dashboard layout"""
        self.app.layout = html.Div([
            html.H1("Hybrid IDS Dashboard", style={'textAlign': 'center'}),
            
            # Statistics Row
            html.Div([
                html.Div(id='live-stats', className='stats-container'),
            ], className='row'),
            
            # Charts Row
            html.Div([
                html.Div([
                    dcc.Graph(id='alerts-by-type'),
                ], className='six columns'),
                
                html.Div([
                    dcc.Graph(id='alerts-by-severity'),
                ], className='six columns'),
            ], className='row'),
            
            # Alerts Table
            html.Div([
                html.H3("Recent Alerts"),
                html.Div(id='alerts-table'),
            ]),
            
            # Update Interval
            dcc.Interval(
                id='interval-component',
                interval=2000,  # Update every 2 seconds
                n_intervals=0
            )
        ])
    
    def setup_callbacks(self):
        """Setup dashboard callbacks"""
        @self.app.callback(
            [Output('live-stats', 'children'),
             Output('alerts-by-type', 'figure'),
             Output('alerts-by-severity', 'figure'),
             Output('alerts-table', 'children')],
            [Input('interval-component', 'n_intervals')]
        )
        def update_dashboard(n):
            stats = self.correlation_engine.get_alert_summary()
            
            # Live Stats
            stats_cards = [
                html.Div([
                    html.H4("Total Alerts"),
                    html.H2(stats.get('total_alerts', 0))
                ], className='stat-card'),
                
                html.Div([
                    html.H4("False Positives"),
                    html.H2(stats.get('false_positives', 0))
                ], className='stat-card'),
                
                html.Div([
                    html.H4("Signature Alerts"),
                    html.H2(stats.get('by_type', {}).get('signature', 0))
                ], className='stat-card'),
                
                html.Div([
                    html.H4("Anomaly Alerts"),
                    html.H2(stats.get('by_type', {}).get('anomaly', 0))
                ], className='stat-card'),
            ]
            
            # Alerts by Type Chart