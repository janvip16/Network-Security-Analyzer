
import pandas as pd
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"

def test_flow_data():
    df = pd.read_csv(DATA_DIR / "flow_summary.csv")
    assert not df.empty
    assert {"flow_id", "src_ip", "dst_ip", "protocol"}.issubset(df.columns)

def test_indicator_data():
    df = pd.read_csv(DATA_DIR / "indicator_feed.csv")
    assert not df.empty
    assert {"indicator", "indicator_type"}.issubset(df.columns)

def test_investigation_cases():
    df = pd.read_csv(DATA_DIR / "indicator_investigation_cases.csv")
    assert not df.empty
    assert {"case_id", "indicator", "expected_handling", "why"}.issubset(df.columns)

if __name__ == "__main__":
    test_flow_data()
    test_indicator_data()
    test_investigation_cases()
    print("All project data tests passed!")
