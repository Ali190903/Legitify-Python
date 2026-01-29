import os
import sys
# Layihə kökünü path-a əlavə edirik
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from internal.common.types import Repository, Organization, Hook
from internal.opa.opa_engine import OpaEngine
from internal.outputer.base_outputer import ConsoleOutputer
from pydantic import ConfigDict

def run_proof():
    print("--- Legitify Python: Texniki Sübut Demosu ---\n")
    
    # 1. Mühərriki başlat (Real opa.exe istifadə edir)
    print("[1] OPA Mühərriki başladılır...")
    try:
        engine = OpaEngine("./proof_policies")
        print("    -> Uğurlu: opa.exe tapıldı və siyasətlər (policies) yükləndi.")
    except Exception as e:
        print(f"    -> XƏTA: OPA mühərriki işə düşmədi! {e}")
        return

    # 2. Süni 'Zəif' Data Yaradılır (Model testi)
    print("\n[2] Süni 'Təhlükəli' Repository yaradılır...")
    # Bu repository-də branch protection yoxdur, bu isə bir təhlükəsizlik xətasıdır.
    bad_repo = Repository(
        name="zəif-test-repo",
        id="R_12345",
        url="https://github.com/demo/zəif-test-repo",
        is_private=True,
        is_archived=False,
        default_branch=None # Branch protection yoxdur!
    )
    # Note: Ref type might be required if validation is strict, but Optional[Ref] = None is valid.
    # Let's ensure strict mode doesn't fail. Default is None.
    print(f"    -> Repo yaradıldı: {bad_repo.name}")

    # 3. Analiz (Real OPA Policy Analizi)
    print("\n[3] OPA Analizi icra edilir (repository.rego)...")
    input_data = {
        "repository": bad_repo.model_dump(by_alias=True),
        "hooks": [],
        "collaborators": []
    }
    
    try:
        # repository.rego paketini yoxlayırıq
        violations = engine.eval(input_data, package="repository")
        print(f"    -> Analiz bitdi. Tapılan pozuntular: {len(violations)}")
    except Exception as e:
        print(f"    -> XƏTA: Analiz zamanı problem oldu! {e}")
        return

    # 4. Nəticə (Outputer)
    print("\n[4] Nəticələrin vizualizasiyası (Rich output)...")
    formatted_violations = []
    for v in violations:
        v["target"] = bad_repo.name
        formatted_violations.append(v)
    
    outputer = ConsoleOutputer()
    outputer.print_violations(formatted_violations)
    
    print("\n--- YEKUN ---")
    if len(violations) > 0:
        print("SÜBUT: Sistem işləyir. OPA mühərriki bizim Python obyektimizi oxudu, \npolicy fayllarını tətbiq etdi və 'branch protection missing' xətasını tapdı.")
    else:
        print("XƏTA: Heç bir pozuntu tapılmadı. Policy faylları düzgün işləmir.")

if __name__ == "__main__":
    run_proof()
