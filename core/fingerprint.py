import re
from typing import Dict, List, Tuple
from config.settings import OS_SIGNATURES

class OSFingerprinting:
    @staticmethod
    def guess_os(ip: str, ports_found: List[int], banners: Dict[int, str]) -> Tuple[str, int]:
        scores: Dict[str, Tuple[int, int]] = {}
        for os_name, sig in OS_SIGNATURES.items():
            score: int = 0
            matched_ports = [p for p in ports_found if p in sig['ports']]
            if matched_ports:
                score += len(matched_ports) * 40

            for banner_data in banners.values():
                if banner_data:
                    for pattern in sig['patterns']:
                        if re.search(pattern, str(banner_data), re.IGNORECASE):
                            score += 50

            if score > 0:
                final_conf = min(100, int(sig['confidence'] * (score / 100) + (40 if matched_ports else 0)))
                scores[os_name] = (score, final_conf)

        if not scores: return ("Unknown", 0)
        best_os = max(scores.items(), key=lambda x: x[1][0])
        return (best_os[0], best_os[1][1])

