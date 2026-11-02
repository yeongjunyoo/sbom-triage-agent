"""영향도 산식과 SBOM 역조회의 버전 비교."""
import pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))
sys.path.insert(0, str(ROOT / "eval"))
from pipeline import impact_of
from where_used import in_ranges, purl_name


def test_impact_scale():
    high = {"internet_facing": True, "data_class": "개인정보"}
    low = {"internet_facing": False, "data_class": "공개"}
    assert impact_of({"kev": True, "epss": 0.0}, high) == (12, "상")
    assert impact_of({"kev": False, "epss": 0.2}, low) == (2, "하")
    assert impact_of({"kev": False, "epss": 0.0}, high) == (4, "중")


def test_version_ranges():
    assert in_ranges("0.14.0", [("0", "0.17.0")])
    assert not in_ranges("0.37.0", [("0", "0.17.0")])
    assert in_ranges("2.14.1", [("2.0", "2.15.0"), ("3.0", None)])


def test_purl_names():
    assert purl_name({"purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}) == "org.apache.logging.log4j:log4j-core"
    assert purl_name({"purl": "pkg:golang/golang.org/x/net@v0.14.0"}) == "golang.org/x/net"
    assert purl_name({"name": "flask"}) == "flask"
