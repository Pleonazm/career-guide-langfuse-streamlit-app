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

# Set page config
st.set_page_config(
    page_title="LangFuse Trace Analyzer",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

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
        self.trace_names = Counter()  # New counter for trace names

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

    def get_traces_list_all(self, **kwargs):
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

    def analyze_traces(self, traces_list):
        """Analyze all traces and count names"""
        for trace in traces_list:
            trace_name = trace.get('name', 'unnamed')
            self.trace_names[trace_name] += 1
            
            # Only detailed analysis for 'validate-field' traces
            if trace_name == 'validate-field':
                self._check_basics(trace)
                self._check_suggestions(trace)
                self._check_warnings(trace)


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
    
    # Date range filter section
    st.sidebar.write("---")
    st.sidebar.write("**📅 Data Filter Options**")
    
#    # Option to filter by recent days
#    use_date_filter = st.sidebar.checkbox("Filter by recent days", value=False)
#    
#    recent_days = None
#    if use_date_filter:
#        filter_type = st.sidebar.radio(
#            "Select filter method:",
#            ["Slider (1-30 days)", "Text input (any number)"],
#            index=0
#        )
#        
#        if filter_type == "Slider (1-30 days)":
#            recent_days = st.sidebar.slider(
#                "Number of recent days:",
#                min_value=1,
#                max_value=30,
#                value=7,
#                help="Fetch data from the last N days"
#            )
#        else:
#            recent_days = st.sidebar.number_input(
#                "Number of recent days:",
#                min_value=1,
#                value=7,
#                help="Enter any number of recent days"
#            )
#        
#        # Show the calculated date range
#        if recent_days:
#            from_date = datetime.now() - timedelta(days=recent_days)
#            st.sidebar.info(f"📊 Fetching data from: {from_date.strftime('%Y-%m-%d')} to today")
#    else:
#        st.sidebar.info("📊 Fetching all available data")
    
    return public_key, secret_key, host, recent_days


def create_charts(analyzer):
    """Create visualization charts"""
    col1, col2 = st.columns(2)
    
    with col1:
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
    
    with col2:
        st.subheader("📊 Trace Names Distribution")
        
        if analyzer.trace_names:
            names_df = pd.DataFrame([
                {'Trace Name': name, 'Count': count} 
                for name, count in analyzer.trace_names.most_common()
            ])
            
            fig_pie = px.pie(names_df, values='Count', names='Trace Name', 
                           title='Distribution of Trace Names')
            st.plotly_chart(fig_pie, use_container_width=True)


def main():
    # Page header
    st.title("📊 LangFuse Trace Analyzer Dashboard")
    st.markdown("---")
    
    # Sidebar
    public_key_override, secret_key_override, host_override, recent_days = create_sidebar()
    
    # Determine which credentials to use
    use_override = any([public_key_override, secret_key_override, host_override])
    
    if use_override and not all([public_key_override, secret_key_override, host_override]):
        st.warning("⚠️ If overriding credentials, please provide all three fields (Public Key, Secret Key, Host)")
        return
    
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
            return
    else:
        st.success("✅ All LangFuse credentials found!")
    
    # Fetch and analyze data
    if recent_days:
        st.info(f"🔄 Fetching traces from the last {recent_days} days...")
    else:
        st.info("🔄 Fetching all available traces from LangFuse...")
    
    try:
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
            return
            
        date_info = f" from the last {recent_days} days" if recent_days else ""
        st.success(f"✅ Loaded {len(all_traces)} traces{date_info} successfully!")
        
        # Analyze traces
        with st.spinner("Analyzing traces..."):
            analyzer.analyze_traces(all_traces)
        
        # Display results
        st.markdown("## 📋 Analysis Results")
        
        # Trace names summary
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Traces", len(all_traces))
        with col2:
            st.metric("Unique Trace Names", len(analyzer.trace_names))
        with col3:
            validate_field_count = analyzer.trace_names.get('validate-field', 0)
            st.metric("'validate-field' Traces", validate_field_count)
        
        # Charts
        create_charts(analyzer)
        
        # Trace Names Table
        st.subheader("📝 Trace Names Summary")
        if analyzer.trace_names:
            names_df = pd.DataFrame([
                {'Trace Name': name, 'Count': count, 'Percentage': f"{(count/len(all_traces)*100):.1f}%"} 
                for name, count in analyzer.trace_names.most_common()
            ])
            st.dataframe(names_df, use_container_width=True)
        
        # Suggestions Table
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
        
        # Warnings Table
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
            
    except Exception as e:
        st.error(f"❌ An error occurred: {str(e)}")
        st.write("Please check your credentials and try again.")

if __name__ == "__main__":
    main()
