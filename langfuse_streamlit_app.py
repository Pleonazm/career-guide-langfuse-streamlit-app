import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import os
from dotenv import load_dotenv, dotenv_values
import requests
from requests.auth import HTTPBasicAuth
from collections import Counter
import json
from datetime import datetime, timedelta
from pathlib import Path
from time import sleep

# Set page config
st.set_page_config(
    page_title="LangFuse Trace Analyzer",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

if 'join_df' not in st.session_state:
    st.session_state['join'] = None

class LangFuseTraceAnalyzer:
    def __init__(self, public_key=None, secret_key=None, host=None):
        # Use provided keys or get from credentials
        if public_key and secret_key and host:
            self.langfuse_credentials = {
                'LANGFUSE_PUBLIC_KEY': public_key,
                'LANGFUSE_SECRET_KEY': secret_key,
                'LANGFUSE_HOST': host
            }
        else:
            self.langfuse_credentials = self._get_langfuse_auth_info()

        self._clear_local()
        


    def _clear_local(self):

        self.processed_ids = set()
        self.fields_counters = {
            'total': Counter(),
            'valid': Counter(), 
            'empty': Counter(),
            'suggestion': Counter(), 
            'warning': Counter()
        }
        self.suggestions = []
        self.warnings = []
        self.trace_names = {}
        self.trace_names_counters = Counter()  # New counter for trace names
        self.usage_data = []
        self.usage_data_traces = {}
        self.usage_data_names = {}
        self.usage_data_summarized = {}
        self.trace_important_data_by_group = {}


    def _get_langfuse_auth_info(self):
        # Load .env file explicitly from current working directory
        env_path = os.path.join(os.getcwd(), '.env')
        load_dotenv(dotenv_path=env_path, override=True)
        
        envs_list = ['LANGFUSE_SECRET_KEY', 'LANGFUSE_PUBLIC_KEY', 'LANGFUSE_HOST']
        auth_data = {}

        for env_var in envs_list:
            value = None
            
            # Try streamlit secrets first (with error handling)
            try:
                if hasattr(st, 'secrets') and st.secrets is not None:
                    # Try lowercase version
                    if env_var.lower() in st.secrets:
                        value = st.secrets[env_var.lower()]
                    # Try original case
                    elif env_var in st.secrets:
                        value = st.secrets[env_var]
                    # Try without LANGFUSE_ prefix
                    elif env_var.replace('LANGFUSE_', '').lower() in st.secrets:
                        value = st.secrets[env_var.replace('LANGFUSE_', '').lower()]
            except (FileNotFoundError, AttributeError):
                # Secrets file doesn't exist, continue to environment variables
                pass
            
            # Fallback to environment variables (from .env or system)
            if not value:
                value = os.getenv(env_var)
            
            auth_data[env_var] = value
            
        return auth_data

    def _get_traces_list(self, **kwargs):
        
        try:
            # If fromTimestamp is provided, try different formats
            if 'fromTimestamp' in kwargs:
                timestamp_formats_to_try = [
                    kwargs['fromTimestamp'],  # Original format
                    kwargs['fromTimestamp'].replace('Z', '+00:00'),  # RFC 3339 format
                    kwargs['fromTimestamp'].split('.')[0] + 'Z',  # Without microseconds
                    kwargs['fromTimestamp'].split('T')[0]  # Date only
                ]
                
                for i, timestamp_format in enumerate(timestamp_formats_to_try):
                    try:
                        params = kwargs.copy()
                        params['fromTimestamp'] = timestamp_format
                        
                        response_trace = requests.get(
                            f"{self.langfuse_credentials['LANGFUSE_HOST']}/api/public/traces",
                            auth=HTTPBasicAuth(
                                self.langfuse_credentials['LANGFUSE_PUBLIC_KEY'], 
                                self.langfuse_credentials['LANGFUSE_SECRET_KEY']
                            ),
                            params=params
                        )
                        response_trace.raise_for_status()
                        return {'status': response_trace.status_code, 'response': response_trace.json()}
                        
                    except requests.exceptions.HTTPError as e:
                        if i == len(timestamp_formats_to_try) - 1:  # Last format attempt
                            st.error(f"Error with timestamp format '{timestamp_format}': {str(e)}")
                            # Try without timestamp as fallback
                            st.warning("Falling back to fetching all data without date filter...")
                            kwargs_no_timestamp = {k: v for k, v in kwargs.items() if k != 'fromTimestamp'}
                            return self._get_traces_list(**kwargs_no_timestamp)
                        continue
            else:
                # No timestamp filtering
                response_trace = requests.get(
                    f"{self.langfuse_credentials['LANGFUSE_HOST']}/api/public/traces",
                    auth=HTTPBasicAuth(
                        self.langfuse_credentials['LANGFUSE_PUBLIC_KEY'], 
                        self.langfuse_credentials['LANGFUSE_SECRET_KEY']
                    ),
                    params=kwargs
                )
                response_trace.raise_for_status()
                return {'status': response_trace.status_code, 'response': response_trace.json()}
                
        except Exception as e:
            st.error(f"Error fetching traces: {str(e)}")
            return None

    def _get_observation_cost_usage(self, observation_item):
        obs_trace = observation_item.get('traceId')
        calc_inp = observation_item.get('calculatedInputCost')
        out_dict = {'id': observation_item.get('id'), 'trace_id': observation_item.get('traceId'), 'name': observation_item.get('name'),}
        usage_keys = {'costDetails': ['input','output', 'total'], 'usageDetails': ['input','output', 'total']}
        for metric_type, metric_list in usage_keys.items():
            if metric_type not in out_dict:
                out_dict[metric_type] = {}
            metric_val = None
            if metric_type not in observation_item:
                continue
            for metric in metric_list:
                try:
                    metric_val = float(observation_item[metric_type].get(metric, None))
                except TypeError:
                    
                    metric_val = 0
                    print (f"CI {calc_inp}## METRIC {metric_type} {metric} ### {observation_item[metric_type]} ### METRIC_VAL {metric_val}")
                    print(out_dict)
                out_dict[metric_type][metric] = metric_val

        return out_dict


    def get_traces_list_all(self, **kwargs):
        self._clear_local()
        full_list = []
        response_base = self._get_traces_list(**kwargs)
        
        if not response_base:
            return full_list
            
        total_pages = response_base['response']['meta']['totalPages']
        
        # Show progress bar
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        for pn in range(total_pages):
            page_num = pn + 1
            status_text.text(f"Loading page {page_num} of {total_pages}...")
            
            pages_response = self._get_traces_list(page=page_num, **kwargs)
            if pages_response:
                pages = pages_response['response']['data']
                full_list.extend(pages)
            
            progress_bar.progress((pn + 1) / total_pages)
        
        progress_bar.empty()
        status_text.empty()
        return full_list

    def _get_input_arg(self, trace_item):
        ret_dict = {'f_name': None, 'f_value': None}
        if trace_item.get('input') is None:
            return ret_dict
        
        if trace_item['input'].get('args') and len(trace_item['input']['args']) > 0:
            ret_dict = {
                'f_value': trace_item['input']['args'][0].get('value'),
                'f_name': trace_item['input']['args'][0].get('field_name')
            }
        else:
            kw_arg = trace_item['input'].get('kwargs', {}).get('request', {})
            ret_dict = {
                'f_value': kw_arg.get('value'),
                'f_name': kw_arg.get('field_name')
            }
        
        return ret_dict

    def _get_output_arg(self, trace_item):
        ret_dict_base = {'valid': '', 'empty': '', 'suggestion': '', 'warning': ''}
        ret_dict = {k: v for k, v in ret_dict_base.items()}
        
        if trace_item.get('output') is None:
            return ret_dict
            
        if 'content' in trace_item['output']:
            out_row = trace_item['output'].get('content', ret_dict_base)
        else:
            out_row = trace_item['output']
        
        for out_arg in ret_dict_base:
            ret_dict[out_arg] = out_row.get(out_arg, '')
        
        return ret_dict

    def _check_basics(self, trace_item):
        input_arg = self._get_input_arg(trace_item)
        output_arg = self._get_output_arg(trace_item)

        if input_arg['f_name']:
            self.fields_counters['total'][input_arg['f_name']] += 1

        if output_arg.get('valid'):
            self.fields_counters['valid'][input_arg['f_name']] += 1

        if input_arg['f_name'] is not None and input_arg['f_value'] is None:
            self.fields_counters['empty'][input_arg['f_name']] += 1

    def _check_warnings(self, trace_item):
        input_arg = self._get_input_arg(trace_item)
        output_arg = self._get_output_arg(trace_item)

        if output_arg.get('warning'):
            self.fields_counters['warning'][input_arg['f_name']] += 1
            warn_dict = {
                'field_name': input_arg['f_name'],
                'raw_value': input_arg['f_value'],
                'warning': output_arg['warning'],
                'trace_id': trace_item['id']
            }
            self.warnings.append(warn_dict)

    def _check_suggestions(self, trace_item):
        input_arg = self._get_input_arg(trace_item)
        output_arg = self._get_output_arg(trace_item)

        if output_arg.get('suggestion'):
            self.fields_counters['suggestion'][input_arg['f_name']] += 1
            suggestion_dict = {
                'field_name': input_arg['f_name'],

                'raw_value': input_arg['f_value'],
                'suggestion': output_arg['suggestion'],
                'trace_id': trace_item['id']
            }
            self.suggestions.append(suggestion_dict)


    def _check_important_info_validate_field(self, trace_item):
        input_arg = self._get_input_arg(trace_item)
        output_arg = self._get_output_arg(trace_item)

#        if field_traces = trace_important_data_by_group['validate-field'].get(input_arg['f_name'], None) is None:
#            trace_important_data_by_group['validate-field'] = []
        info_dict = {'trace_id': trace_item['id'], 'field_name':input_arg['f_name'], 'field_value':input_arg['f_value']}        
        self.trace_important_data_by_group['validate-field'].append(info_dict)
#        self.trace_important_data_by_group['validate-field'][trace_item['id']] = info_dict
        



    def _check_usage3(self):
        print('CHECK USAGE 3')

        
        
        obs_response = requests.get(
                f"{self.langfuse_credentials['LANGFUSE_HOST']}/api/public/observations",
                params={
                  "limit": "50",
                "type": "GENERATION"
                },
                auth=HTTPBasicAuth(
                                            self.langfuse_credentials['LANGFUSE_PUBLIC_KEY'], 
                                            self.langfuse_credentials['LANGFUSE_SECRET_KEY']
            ))
        obs_data = obs_response.json()
        total_pages = obs_data['meta']['totalPages']

########TMP NEW ALL


        for pn in range(total_pages):
            page_num = pn + 1
            obs_response = requests.get(
                f"{self.langfuse_credentials['LANGFUSE_HOST']}/api/public/observations",
                params={
                  "page": f"{page_num}",
                "type": "GENERATION"
                },
                auth=HTTPBasicAuth(self.langfuse_credentials['LANGFUSE_PUBLIC_KEY'], self.langfuse_credentials['LANGFUSE_SECRET_KEY']
            ))
            obs_data = obs_response.json()
            obs_data_clean = [o for o in obs_data['data'] if o['traceId'] in self.trace_names.keys()]
            for o in obs_data_clean:
#        for o in obs_data['data']:
                print(f"obs_id {o['id']}, obs_trace {o['traceId']}")
                obs_usage = self._get_observation_cost_usage(o)
                self.usage_data.append(obs_usage)
                if not self.usage_data_traces.get(obs_usage['trace_id'], None):
                    self.usage_data_traces[obs_usage['trace_id']] = []
                self.usage_data_traces[obs_usage['trace_id']].append({'o_id':o['id'],'usage_cost':obs_usage})

##############OLD BUT WORKING FOR LIMIT 50

#         obs_data_clean = [o for o in obs_data['data'] if o['traceId'] in self.trace_names.keys()]
#         for o in obs_data_clean:
# #        for o in obs_data['data']:
#             print(f"obs_id {o['id']}, obs_trace {o['traceId']}")
#             obs_usage = self._get_observation_cost_usage(o)
#             self.usage_data.append(obs_usage)
#             if not self.usage_data_traces.get(obs_usage['trace_id'], None):
#                 self.usage_data_traces[obs_usage['trace_id']] = []
#             self.usage_data_traces[obs_usage['trace_id']].append({'o_id':o['id'],'usage_cost':obs_usage})
            





    def summarize_usage_data(self):
        """
        Summarizes costs and usage from all observations grouped by trace_id.
        
        Aggregates data from self.usage_data_traces and stores the result in 
        self.usage_data_summarized with schema:
        {
            trace_id: {
                'costDetails': {'input': float, 'output': float, 'total': float},
                'usageDetails': {'input': int, 'output': int, 'total': int}
            }
        }
        """
        self.usage_data_summarized = {}
        self.usage_data_summarized2 = []
        # Iterate through all trace_ids in the source data
        for trace_id, observations in self.usage_data_traces.items():
            trace_obs_number = 0
            trace_name = self.trace_names[trace_id]
            # Initialize aggregated values for this trace
            total_cost_input = 0.0
            total_cost_output = 0.0
            total_cost_total = 0.0
            
            total_usage_input = 0
            total_usage_output = 0
            total_usage_total = 0
            
            # Iterate through all observations for this trace
            for observation in observations:
                usage_cost = observation.get('usage_cost', {})
                trace_obs_number += 1
                
                # Aggregate cost details
                cost_details = usage_cost.get('costDetails', {})
                total_cost_input += cost_details.get('input', 0.0)
                total_cost_output += cost_details.get('output', 0.0)
                total_cost_total += cost_details.get('total', 0.0)
                
                # Aggregate usage details
                usage_details = usage_cost.get('usageDetails', {})
                total_usage_input += usage_details.get('input', 0)
                total_usage_output += usage_details.get('output', 0)
                total_usage_total += usage_details.get('total', 0)
            
            # Store summarized data for this trace
#                self.usage_data_summarized[trace_id] = {
            self.usage_data_summarized[trace_id] = {
                'observations_count': trace_obs_number, 'trace_name': trace_name,
                'costDetails_input': total_cost_input,
                'costDetails_output': total_cost_output,
                'costDetails_total': total_cost_total,
                
            
                    'usageDetails_input': total_usage_input,
                    'usageDetails_output': total_usage_output,
                    'usageDetails_total': total_usage_total
                }
            self.usage_data_summarized2.append({
                'observations_count': trace_obs_number, 'trace_name': trace_name, 'trace_id':trace_id, 
                'costDetails_input': total_cost_input,
                'costDetails_output': total_cost_output,
                'costDetails_total': total_cost_total,
                
            
                    'usageDetails_input': total_usage_input,
                    'usageDetails_output': total_usage_output,
                    'usageDetails_total': total_usage_total
                })            




#            self.usage_data_summarized[trace_id] = {
#                'observations_count': trace_obs_number, 'trace_name': trace_name,
#                'costDetails': {
#                    'input': total_cost_input,
#                    'output': total_cost_output,
#                    'total': total_cost_total
#                },
#                'usageDetails': {
#                    'input': total_usage_input,
#                    'output': total_usage_output,
#                    'total': total_usage_total
#                }
#            }
        
#        return self.usage_data_summarized




    def analyze_traces(self, traces_list):
        """Analyze all traces and count names"""

        self._clear_local()

        #TMP Add group
        self.trace_important_data_by_group['validate-field'] = []

        for trace in traces_list:
            self.trace_important_data_by_group['validate-field'].append({'trace_id':trace.get('id', 'no_trace_id')})

            self.trace_names.update({trace.get('id', 'no_trace_id'):trace.get('name', 'unnamed')})
            trace_name = trace.get('name', 'unnamed')
            self.trace_names_counters[trace_name] += 1
            
            # Only detailed analysis for 'validate-field' traces
            if trace_name == 'validate-field':
                self._check_basics(trace)
                self._check_suggestions(trace)
                self._check_warnings(trace)
#                self._check_usage(trace)
                self._check_important_info_validate_field(trace)
        self._check_usage3()
        self.summarize_usage_data()
#        self._summarize_observations_traces()

##############################################STREAMLIT##########################

def create_sidebar():
    """Create sidebar for credential override"""
    # Option to filter by recent days
    use_date_filter = st.sidebar.checkbox("Filter by recent days", value=False)
    
    recent_days = None
    if use_date_filter:
        filter_type = st.sidebar.radio(
            "Select filter method:",
            ["Slider (1-30 days)", "Text input (any number)"],
            index=0
        )
        
        if filter_type == "Slider (1-30 days)":
            recent_days = st.sidebar.slider(
                "Number of recent days:",
                min_value=1,
                max_value=30,
                value=7,
                help="Fetch data from the last N days"
            )
        else:
            recent_days = st.sidebar.number_input(
                "Number of recent days:",
                min_value=1,
                value=7,
                help="Enter any number of recent days"
            )
        
        # Show the calculated date range
        if recent_days:
            from_date = datetime.now() - timedelta(days=recent_days)
            st.sidebar.info(f"📊 Fetching data from: {from_date.strftime('%Y-%m-%d')} to today")
    else:
        st.sidebar.info("📊 Fetching all available data")


    st.sidebar.header("🔑 LangFuse Credentials")
    
    # Check if credentials are available (with error handling)
    try:
        analyzer_temp = LangFuseTraceAnalyzer()
        current_creds = analyzer_temp.langfuse_credentials
        
        # Show current credential status
        st.sidebar.write("**Current Credentials Status:**")
        has_all_creds = True
        for key, value in current_creds.items():
            if value:
                st.sidebar.success(f"✅ {key.replace('LANGFUSE_', '')}")
            else:
                st.sidebar.error(f"❌ {key.replace('LANGFUSE_', '')}")
                has_all_creds = False
        
        if not has_all_creds:
            st.sidebar.warning("⚠️ Some credentials are missing. Please provide them below.")
    
    except Exception as e:
        st.sidebar.error(f"Error loading credentials: {str(e)}")
        has_all_creds = False
    
    st.sidebar.write("---")
    st.sidebar.write("**Provide/Override Credentials:**")
    
    # Always show override inputs
    public_key = st.sidebar.text_input(
        "Public Key", 
        value="", 
        type="password",
        help="Provide or override the public key",
        placeholder="Enter your LangFuse public key"
    )
    secret_key = st.sidebar.text_input(
        "Secret Key", 
        value="", 
        type="password",
        help="Provide or override the secret key",
        placeholder="Enter your LangFuse secret key"
    )
    host = st.sidebar.text_input(
        "Host URL", 
        value="",
        help="Provide or override the host URL",
        placeholder="e.g., https://cloud.langfuse.com"
    )
    
    # Show example .env format
    st.sidebar.write("---")
    st.sidebar.write("**Example .env file format:**")
    st.sidebar.code("""LANGFUSE_PUBLIC_KEY=pk-lf-...
LANGFUSE_SECRET_KEY=sk-lf-...
LANGFUSE_HOST=https://cloud.langfuse.com""")
    
    # Show current working directory for .env reference
    st.sidebar.write(f"**Looking for .env in:** `{os.getcwd()}`")
    
    # Check if .env file exists
    env_file_path = os.path.join(os.getcwd(), '.env')
    if os.path.exists(env_file_path):
        st.sidebar.success("✅ .env file found")
    else:
        st.sidebar.info("ℹ️ No .env file found")
#    self.usage_data_summarized
    # Date range filter section
    st.sidebar.write("---")
    st.sidebar.write("**📅 Data Filter Options**")


    
    return public_key, secret_key, host, recent_days


def create_validate_field_charts(analyzer):
    """Create charts specifically for validate-field analysis"""
    st.subheader("📈 Field Analysis Overview (only 'validate-field' traces!!!)")
    
    # Prepare data for stacked bar chart
    fields = list(analyzer.fields_counters['total'].keys())
    if fields:
        chart_data = {
            'Field': fields,
            'Total': [analyzer.fields_counters['total'][f] for f in fields],
            'Valid': [analyzer.fields_counters['valid'][f] for f in fields],
            'Empty': [analyzer.fields_counters['empty'][f] for f in fields],
            'Suggestions': [analyzer.fields_counters['suggestion'][f] for f in fields],
            'Warnings': [analyzer.fields_counters['warning'][f] for f in fields]
        }
        df_chart = pd.DataFrame(chart_data)
        fig = go.Figure()
        fig.add_trace(go.Bar(name='Valid', x=df_chart['Field'], y=df_chart['Valid'], marker_color='green'))
        fig.add_trace(go.Bar(name='Empty', x=df_chart['Field'], y=df_chart['Empty'], marker_color='lightgray'))
        fig.add_trace(go.Bar(name='Suggestions', x=df_chart['Field'], y=df_chart['Suggestions'], marker_color='orange'))
        fig.add_trace(go.Bar(name='Warnings', x=df_chart['Field'], y=df_chart['Warnings'], marker_color='red'))
        fig.update_layout(barmode='stack', title='Field Validation Results')
        st.plotly_chart(fig, use_container_width=True)


def create_trace_names_distribution_chart(analyzer):
    """Create trace names distribution pie chart"""
    st.subheader("📊 Trace Names Distribution")
    
    if analyzer.trace_names_counters:
        names_df = pd.DataFrame([
            {'Trace Name': name, 'Count': count}
            for name, count in analyzer.trace_names_counters.most_common()
        ])
        fig_pie = px.pie(names_df, values='Count', names='Trace Name',
                        title='Distribution of Trace Names')
        st.plotly_chart(fig_pie, use_container_width=True)


def create_charts(analyzer):
    """Create visualization charts"""
    col1, col2 = st.columns(2)
    
    with col1:
        create_validate_field_charts(analyzer)
    
    with col2:
        create_trace_names_distribution_chart(analyzer)


# def create_charts(analyzer):
#     """Create visualization charts"""
#     col1, col2 = st.columns(2)
    
#     with col1:
#         st.subheader("📈 Field Analysis Overview (only 'validate-field' traces!!!)")
        
#         # Prepare data for stacked bar chart
#         fields = list(analyzer.fields_counters['total'].keys())
#         if fields:
#             chart_data = {
#                 'Field': fields,
#                 'Total': [analyzer.fields_counters['total'][f] for f in fields],
#                 'Valid': [analyzer.fields_counters['valid'][f] for f in fields],
#                 'Empty': [analyzer.fields_counters['empty'][f] for f in fields],
#                 'Suggestions': [analyzer.fields_counters['suggestion'][f] for f in fields],
#                 'Warnings': [analyzer.fields_counters['warning'][f] for f in fields]
#             }
            
#             df_chart = pd.DataFrame(chart_data)
            
#             fig = go.Figure()
            
#             fig.add_trace(go.Bar(name='Valid', x=df_chart['Field'], y=df_chart['Valid'], marker_color='green'))
#             fig.add_trace(go.Bar(name='Empty', x=df_chart['Field'], y=df_chart['Empty'], marker_color='lightgray'))
#             fig.add_trace(go.Bar(name='Suggestions', x=df_chart['Field'], y=df_chart['Suggestions'], marker_color='orange'))
#             fig.add_trace(go.Bar(name='Warnings', x=df_chart['Field'], y=df_chart['Warnings'], marker_color='red'))
            
#             fig.update_layout(barmode='stack', title='Field Validation Results')
#             st.plotly_chart(fig, use_container_width=True)
    
#     with col2:
#         st.subheader("📊 Trace Names Distribution")
        
#         if analyzer.trace_names_counters:
#             names_df = pd.DataFrame([
#                 {'Trace Name': name, 'Count': count} 
#                 for name, count in analyzer.trace_names_counters.most_common()
#             ])
            
#             fig_pie = px.pie(names_df, values='Count', names='Trace Name', 
#                            title='Distribution of Trace Names')
#             st.plotly_chart(fig_pie, use_container_width=True)

# def create_page_header():
#     # Page header
#     st.title("📊 LangFuse Trace Analyzer Dashboard")
#     st.markdown("---")


# def create_general_tab():
#     pass

# def create_field_validation_tab():
#     pass

# def create_profile_sections_tab():
#     pass


# def main():
#     # # Page header
#     # st.title("📊 LangFuse Trace Analyzer Dashboard")
#     # st.markdown("---")

#     create_page_header()
    
#     # Sidebar
#     public_key_override, secret_key_override, host_override, recent_days = create_sidebar()

#     tab_general_info, tab_field_validation, tab_profile_sections = st.tabs(['General', 'Field Validation', 'Profile'])
    
#     # Determine which credentials to use
#     use_override = any([public_key_override, secret_key_override, host_override])
        
#     if use_override and not all([public_key_override, secret_key_override, host_override]):
#         st.warning("⚠️ If overriding credentials, please provide all three fields (Public Key, Secret Key, Host)")
#         return
    
#     # Initialize analyzer
#     if use_override:
#         analyzer = LangFuseTraceAnalyzer(
#             public_key=public_key_override,
#             secret_key=secret_key_override, 
#             host=host_override
#         )
#     else:
#         analyzer = LangFuseTraceAnalyzer()
    
#     # Check if credentials are available
#     missing_creds = not all(analyzer.langfuse_credentials.values())
    
    
#     if missing_creds:
#         st.error("❌ Missing LangFuse credentials. Please provide them via:")
#         st.write("1. **Environment variables** in `.env` file (same directory as script)")
#         st.write("2. **Streamlit secrets** (recommended for deployment)")
#         st.write("3. **Sidebar form** (fill out the fields in the sidebar)")
#         st.write("")
#         st.info("💡 If you have a `.env` file, make sure it's in the same directory as this script and contains the variables shown in the sidebar.")
        
#         # Still show the interface but with a warning
#         if not use_override:
#             st.warning("⚠️ Please provide credentials using the sidebar form to proceed.")
#             return
#     else:
#         st.success("✅ All LangFuse credentials found!")
    
#     # Fetch and analyze data
#     if recent_days:
#         st.info(f"🔄 Fetching traces from the last {recent_days} days...")
#     else:
#         st.info("🔄 Fetching all available traces from LangFuse...")
    
#     try:
        
#         with st.spinner("Loading traces..."):
#             # Prepare API parameters for date filtering
#             api_params = {}
#             if recent_days:
#                 # Calculate the from_timestamp for the API
#                 from_datetime = datetime.now() - timedelta(days=recent_days)
#                 # Start with the most common ISO format
#                 api_params['fromTimestamp'] = from_datetime.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            
#             all_traces = analyzer.get_traces_list_all(**api_params)
            
#         if not all_traces:
#             st.warning("No traces found or error occurred while fetching data.")
#             if recent_days:
#                 st.info(f"💡 Try increasing the number of days (currently set to {recent_days}) or disable date filtering to see all data.")
#             return
            
#         date_info = f" from the last {recent_days} days" if recent_days else ""
#         st.success(f"✅ Loaded {len(all_traces)} traces{date_info} successfully!")
        
#         # Analyze traces
#         with st.spinner("Analyzing traces..."):
#             analyzer._clear_local()
#             analyzer.analyze_traces(all_traces)
            
#         # Display results
#         st.markdown("## 📋 Analysis Results")
        
#         # Trace names summary
#         col1, col2, col3 = st.columns(3)
#         with col1:
#             st.metric("Total Traces", len(all_traces))
#         with col2:
#             st.metric("Unique Trace Names", len(analyzer.trace_names_counters))
#         with col3:
#             validate_field_count = analyzer.trace_names_counters.get('validate-field', 0)
#             st.metric("'validate-field' Traces", validate_field_count)
        
#         # Charts
#         create_charts(analyzer)
        
#         # Trace Names Table
#         st.subheader("📝 Trace Names Summary")
#         if analyzer.trace_names_counters:
#             names_df = pd.DataFrame([
#                 {'Trace Name': name, 'Count': count, 'Percentage': f"{(count/len(all_traces)*100):.1f}%"} 
#                 for name, count in analyzer.trace_names_counters.most_common()
#             ])
#             st.dataframe(names_df, use_container_width=True)
        
#         # Suggestions Table
#         st.subheader("💡 Suggestions")
#         if analyzer.suggestions:
#             suggestions_df = pd.DataFrame(analyzer.suggestions)
#             st.dataframe(suggestions_df, use_container_width=True)
            
#             # Download button for suggestions
#             csv_suggestions = suggestions_df.to_csv(index=False)
#             st.download_button(
#                 label="📥 Download Suggestions as CSV",
#                 data=csv_suggestions,
#                 file_name="langfuse_suggestions.csv",
#                 mime="text/csv"
#             )
#         else:
#             st.info("No suggestions found in the analyzed traces.")
        
#         # Warnings Table
#         st.subheader("⚠️ Warnings")
#         if analyzer.warnings:
#             warnings_df = pd.DataFrame(analyzer.warnings)
#             st.dataframe(warnings_df, use_container_width=True)
            
#             # Download button for warnings
#             csv_warnings = warnings_df.to_csv(index=False)
#             st.download_button(
#                 label="📥 Download Warnings as CSV",
#                 data=csv_warnings,
#                 file_name="langfuse_warnings.csv",
#                 mime="text/csv"
#             )
#         else:
# #            self.usage_data_summarized()
#             st.info("No warnings found in the analyzed traces.")
#         #DEBUG INFO
# #        st.subheader("⚠️ names")
# #        st.write(analyzer.trace_names)
# #        st.subheader("⚠️ Usage")
# #        st.write(analyzer.usage_data)
# #        st.subheader("⚠️ Usafge Trace")
# #        st.write(analyzer.usage_data_traces)
# #        st.subheader("⚠️ Usage Trace Summ")
# #        st.write(analyzer.usage_data_summarized)
# #        st.subheader("⚠️ Usage Trace Summ2")
#         st.subheader("📊 Validate Field Use/Cost")
#         with st.expander("Validate-Field: Raw Cost/Usage Per Trace"):
# #        st.subheader("⚠️ Raw Cost/Usage Per Trace")
#             sdf = pd.DataFrame(analyzer.usage_data_summarized)
#             sdf2 = pd.DataFrame(analyzer.usage_data_summarized2)
# #        st.write(analyzer.usage_data_summarized)
#             st.write(sdf)
# #        st.write(analyzer.usage_data_summarized2)
#             st.write(sdf2)
        
#         imp_data_vf = [f for f in analyzer.trace_important_data_by_group['validate-field'] if 'field_name' in f]

#         imp_df1 = pd.DataFrame(analyzer.trace_important_data_by_group)
#         imp_df2 = pd.DataFrame(imp_data_vf)
#         if analyzer.trace_names_counters.get('validate-field', 0) > 0:
#             with st.expander("Validate-Field: Fields Values"):
#     #            st.write(imp_df1)
#                 st.write(imp_df2)
#             join_df = imp_df2.merge(sdf2, on='trace_id', how='inner')
#             with st.expander("Validate-Field: Join Data and Cost"):
#                 st.subheader("Calculation per field (Cost)")
#                 st.write(join_df.groupby('field_name', as_index=False)[['costDetails_input', 'costDetails_output', 'costDetails_total',]].agg(['min','max', 'mean']))
#                 st.subheader("Calculation per field (Usage)")
#                 st.write(join_df.groupby('field_name', as_index=False)[['usageDetails_input', 'usageDetails_output', 'usageDetails_total']].agg(['min','max', 'mean']))
#                 st.subheader("Raw Join")
#                 st.write(join_df)
                
#     except Exception as e:
#         raise e
#         st.error(f"❌ An error occurred: {str(e)}")
#         st.write("Please check your credentials and try again.")

# if __name__ == "__main__":
#     main()

def create_page_header():
    # Page header
    st.title("📊 LangFuse Trace Analyzer Dashboard")
    st.markdown("---")


def validate_and_initialize_credentials(public_key_override, secret_key_override, host_override):
    """Validate credentials and initialize analyzer"""
    # Determine which credentials to use
    use_override = any([public_key_override, secret_key_override, host_override])
        
    if use_override and not all([public_key_override, secret_key_override, host_override]):
        st.warning("⚠️ If overriding credentials, please provide all three fields (Public Key, Secret Key, Host)")
        return None, False
    
    # Initialize analyzer
    if use_override:
        analyzer = LangFuseTraceAnalyzer(
            public_key=public_key_override,
            secret_key=secret_key_override, 
            host=host_override
        )
    else:
        analyzer = LangFuseTraceAnalyzer()
    
    # Check if credentials are available
    missing_creds = not all(analyzer.langfuse_credentials.values())
    
    if missing_creds:
        st.error("❌ Missing LangFuse credentials. Please provide them via:")
        st.write("1. **Environment variables** in `.env` file (same directory as script)")
        st.write("2. **Streamlit secrets** (recommended for deployment)")
        st.write("3. **Sidebar form** (fill out the fields in the sidebar)")
        st.write("")
        st.info("💡 If you have a `.env` file, make sure it's in the same directory as this script and contains the variables shown in the sidebar.")
        
        # Still show the interface but with a warning
        if not use_override:
            st.warning("⚠️ Please provide credentials using the sidebar form to proceed.")
            return None, False
    else:
        st.success("✅ All LangFuse credentials found!")
    
    return analyzer, True


def fetch_traces_data(analyzer, recent_days):
    """Fetch traces data from LangFuse"""
    # Display loading message
    if recent_days:
        st.info(f"🔄 Fetching traces from the last {recent_days} days...")
    else:
        st.info("🔄 Fetching all available traces from LangFuse...")
    
    with st.spinner("Loading traces..."):
        # Prepare API parameters for date filtering
        api_params = {}
        if recent_days:
            # Calculate the from_timestamp for the API
            from_datetime = datetime.now() - timedelta(days=recent_days)
            # Start with the most common ISO format
            api_params['fromTimestamp'] = from_datetime.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        
        all_traces = analyzer.get_traces_list_all(**api_params)
        
    if not all_traces:
        st.warning("No traces found or error occurred while fetching data.")
        if recent_days:
            st.info(f"💡 Try increasing the number of days (currently set to {recent_days}) or disable date filtering to see all data.")
        return None
        
    date_info = f" from the last {recent_days} days" if recent_days else ""
    st.success(f"✅ Loaded {len(all_traces)} traces{date_info} successfully!")
    
    return all_traces


def analyze_traces_data(analyzer, all_traces):
    """Analyze the fetched traces"""
    with st.spinner("Analyzing traces..."):
        analyzer._clear_local()
        analyzer.analyze_traces(all_traces)


def display_metrics_summary(analyzer, all_traces):
    """Display summary metrics"""
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Traces", len(all_traces))
    with col2:
        st.metric("Unique Trace Names", len(analyzer.trace_names_counters))
    # with col3:
    #     validate_field_count = analyzer.trace_names_counters.get('validate-field', 0)
    #     st.metric("'validate-field' Traces", validate_field_count)


def display_trace_names_table(analyzer, all_traces):
    """Display trace names summary table"""
    st.subheader("📝 Trace Names Summary")
    if analyzer.trace_names_counters:
        names_df = pd.DataFrame([
            {'Trace Name': name, 'Count': count, 'Percentage': f"{(count/len(all_traces)*100):.1f}%"} 
            for name, count in analyzer.trace_names_counters.most_common()
        ])
        st.dataframe(names_df, use_container_width=True)


def display_suggestions_table(analyzer):
    """Display suggestions table with download option"""
    st.subheader("💡 Suggestions")
    if analyzer.suggestions:
        suggestions_df = pd.DataFrame(analyzer.suggestions)
        st.dataframe(suggestions_df, use_container_width=True)
        
        # Download button for suggestions
        csv_suggestions = suggestions_df.to_csv(index=False)
        st.download_button(
            label="📥 Download Suggestions as CSV",
            data=csv_suggestions,
            file_name="langfuse_suggestions.csv",
            mime="text/csv"
        )
    else:
        st.info("No suggestions found in the analyzed traces.")


def display_warnings_table(analyzer):
    """Display warnings table with download option"""
    st.subheader("⚠️ Warnings")
    if analyzer.warnings:
        warnings_df = pd.DataFrame(analyzer.warnings)
        st.dataframe(warnings_df, use_container_width=True)
        
        # Download button for warnings
        csv_warnings = warnings_df.to_csv(index=False)
        st.download_button(
            label="📥 Download Warnings as CSV",
            data=csv_warnings,
            file_name="langfuse_warnings.csv",
            mime="text/csv"
        )
    else:
        st.info("No warnings found in the analyzed traces.")


def display_validate_field_analysis(analyzer):
    """Display validate-field specific analysis"""
    st.subheader("📊 Validate Field Use/Cost")
    
    # Raw cost/usage per trace
    with st.expander("Validate-Field: Raw Cost/Usage Per Trace"):
        sdf = pd.DataFrame(analyzer.usage_data_summarized)
        sdf2 = pd.DataFrame(analyzer.usage_data_summarized2)
        st.write(sdf)
        st.write(sdf2)
    
    # Field values analysis
    imp_data_vf = [f for f in analyzer.trace_important_data_by_group['validate-field'] if 'field_name' in f]
    imp_df2 = pd.DataFrame(imp_data_vf)
    
    if analyzer.trace_names_counters.get('validate-field', 0) > 0:
        with st.expander("Validate-Field: Fields Values"):
            st.write(imp_df2)
        
        # Join data and cost analysis
        # join_df = imp_df2.merge(sdf2, on='trace_id', how='inner')
        join_df = imp_df2.merge(sdf2, on='trace_id', how='outer')
        st.session_state['join_df'] = join_df
        with st.expander("Validate-Field: Join Data and Cost"):
            st.subheader("Calculation per field (Cost)")
            st.write(join_df.groupby('field_name', as_index=False)[['costDetails_input', 'costDetails_output', 'costDetails_total']].agg(['min','max', 'mean']))
            st.subheader("Calculation per field (Usage)")
            st.write(join_df.groupby('field_name', as_index=False)[['usageDetails_input', 'usageDetails_output', 'usageDetails_total']].agg(['min','max', 'mean']))
            st.subheader("Raw Join")
            st.write(join_df)

            ##TMP
            p1fields = ['first_name', 'last_name']
            df_copy = join_df.copy()
            df_prof1 = df_copy[df_copy['field_name'].isin(p1fields)]
            st.write(df_prof1)


def display_analysis_results_general(analyzer, all_traces):
    """Display all analysis results"""
    st.markdown("## 📋 Analysis Results")
    
    # Metrics summary
    display_metrics_summary(analyzer, all_traces)
    
    # Charts
    # create_charts(analyzer)
    create_trace_names_distribution_chart(analyzer)
    
    # Trace Names Table
    display_trace_names_table(analyzer, all_traces)
    
    # # Suggestions Table
    # display_suggestions_table(analyzer)
    
    # # Warnings Table
    # display_warnings_table(analyzer)
    
    # # Validate Field Analysis
    # display_validate_field_analysis(analyzer)

def display_analysis_result_validate_field(analyzer, all_traces):

    # st.markdown('## Trace Validate-Field')
    # st.write('Used by Profile Wizard when validating each form field')

    # Suggestions Table
    display_suggestions_table(analyzer)
    
    # Warnings Table
    display_warnings_table(analyzer)
    
    # Validate Field Analysis
    display_validate_field_analysis(analyzer)


def main():
    # Page header
    create_page_header()
    
    
    
    # Sidebar
    public_key_override, secret_key_override, host_override, recent_days = create_sidebar()

    # Wrap the main data processing in try/except as in original code
    try:
        with st.expander('Basic Diagnostic Info'):
            # Validate credentials and initialize analyzer
            analyzer, credentials_valid = validate_and_initialize_credentials(
                public_key_override, secret_key_override, host_override
            )
            
            if not credentials_valid:
                return
            
    
    
            # Fetch traces data
            all_traces = fetch_traces_data(analyzer, recent_days)
            if not all_traces:
                return
        
        # Analyze traces
        analyze_traces_data(analyzer, all_traces)
        tab_general, tab_validate_fields, tab_profile_steps = st.tabs(['General Info', 'Trace Validate-Field', 'Profile Steps'])
        # Display results
        with tab_general:
            display_analysis_results_general(analyzer, all_traces)
        with tab_validate_fields:
            st.markdown('## Trace Validate-Field')
            st.write('Used by Profile Wizard when validating each form field')  
            create_validate_field_charts(analyzer)
            display_analysis_result_validate_field(analyzer, all_traces)
        with tab_profile_steps:

            #Assignment fields into Wizard steps

            carrier_goal_step_tmp = ['career_goals_short_term', 'short', 'career_goals_long_term', 'career_goals_industries']
            skill_step_tmp = ['tech', 'soft']
            
            # st.header('MANUAL CREATION TESTING')
            basic_info_step = ['first_name', 'last_name', 'email', 'title', 'location', 'phone', 'linkedin', 'website']
            carrier_goal_step = ['career_goals_short_term', 'career_goals_long_term', 'career_goals_industries',
                                 'short',
                                 'preferred_work_location', 'work_remote', 'work_hybrid', 'work_office',
                                 'team_size_preference',
                                 'language', 'level',
                                 'preferred_contract_type', 'preferred_employment_type', 'travel_willing']
            skill_step = ['tech_skills', 'soft_skills']
            experience_step = ['experience']#TODO
            education_step = ['education', 'degree', 'institution']#TODO
            courses_step = ['name', 'institution', 'month']
            projects_step = ['name', 'start_date', 'end_date', 'description']
            interests_step = ['interests']
            summary_step = []#TODO?

            # with st.expander('Basic Step Info'):
            #     st.write('All traces from Step')
            #     df_copy = st.session_state['join_df'].copy()
            #     df_basic:pd.DataFrame = df_copy[df_copy['field_name'].isin(basic_info_step)]
            #     st.write(df_basic)
            #     st.write('Describe Step')
    
            #     st.write(df_basic.describe())
            #     st.write('Step field list')
            #     st.write(basic_info_step)

            # with st.expander('Career Goals Info'):
            #     st.write('All traces from Step')
            #     df_copy = st.session_state['join_df'].copy()
            #     df_cg:pd.DataFrame = df_copy[df_copy['field_name'].isin(carrier_goal_step_tmp)]
            #     st.write(df_cg)
            #     st.write('Describe Step')
    
            #     st.write(df_cg.describe())
            #     st.write('Step field list')
            #     st.write(carrier_goal_step_tmp)
    

                # st.write(df_cg)
            st.header('Summary for each Profile Wizard Step')
            step_fields_dict = {
                        #    'carrier_goal_step_tmp' : ['career_goals_short_term', 'short', 'career_goals_industries'],
                            # 'skill_step_tmp' : ['tech', 'soft'],
            
            
                            'basic_info_step' : ['first_name', 'last_name', 'email', 'title', 'location', 'phone', 'linkedin', 'website'],
                            'carrier_goal_step' : ['career_goals_short_term', 'career_goals_long_term', 'career_goals_industries',
                                 'short',
                                 'preferred_work_location', 'work_remote', 'work_hybrid', 'work_office',
                                 'team_size_preference',
                                 'language', 'level',
                                 'preferred_contract_type', 'preferred_employment_type', 'travel_willing'],
                            'skill_step' : ['tech_skills', 'soft_skills'],
                            'experience_step' : ['experience'],#TODO
                            'education_step' : ['education', 'degree', 'institution'],#TODO
                            'courses_step' : ['name', 'institution', 'month'],
                            'projects_step' : ['name', 'start_date', 'end_date', 'description'],
                            'interests_step' : ['interests'],
                            'summary_step' : []#TODO?
            }
            expander_names_map = {
                'basic_info_step': 'Basic Info',
                'carrier_goal_step': 'Carrier Goals',
                'skill_step': 'Skills',
                'experience_step': 'Experience',
                'courses_step': 'Courses',
                'projects_step': 'Projects',
                'interests_step': 'Interests',


                }
            for step_name, step_fields in step_fields_dict.items():
                expander_name = expander_names_map.get(f"{step_name}", step_name)
                with st.expander(f'Step: {expander_name}'):
                    
                    df_copy = st.session_state['join_df'].copy()
                    df_basic:pd.DataFrame = df_copy[df_copy['field_name'].isin(step_fields)]
                    with st.popover('Raw Records', use_container_width=True):
                        st.write('Raw Records')
                        st.write(df_basic)
                    st.write('Basic summary (Pandas DF Describe)')
                    if df_basic.empty:
                        st.write('Empty DF. Nothing to describe')
                    else:
                        st.write(df_basic.describe())
                    st.markdown("**Fields in Step**")
                    st.write(step_fields)



    except Exception as e:
        raise e
        st.error(f"❌ An error occurred: {str(e)}")
        st.write("Please check your credentials and try again.")


if __name__ == "__main__":
    main()