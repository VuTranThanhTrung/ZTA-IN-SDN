import datetime
from threading import Lock
from typing import Dict, Any

class DynamicPolicyEngine:
    """
    DynamicPolicyEngine manages dynamic trust scores per host and determines
    mitigation actions based on zero-trust policy guidelines.
    """
    def __init__(self, logger: Any = None, recovery_step: float = 0.02) -> None:
        """
        Initialize the Dynamic Policy Engine.

        Args:
            logger: Optional logger instance.
        """
        self.logger: Any = logger
        self.trust_scores: Dict[str, float] = {}
        self.penalties_count: Dict[str, int] = {}
        self.recovery_step: float = recovery_step
        self.lock: Lock = Lock()

    def update_trust_score(self, ip_address: str, penalty: float) -> float:
        """
        Update the trust score of a host by subtracting the penalty.

        Args:
            ip_address: The IP address of the host.
            penalty: The penalty value to apply.

        Returns:
            The updated trust score, bounded between 0.0 and 1.0.
        """
        with self.lock:
            if ip_address not in self.trust_scores:
                self.trust_scores[ip_address] = 1.0
                self.penalties_count[ip_address] = 0

            old_score: float = self.trust_scores[ip_address]
            new_score: float = max(0.0, min(1.0, old_score - penalty))
            self.trust_scores[ip_address] = new_score

            if penalty > 0:
                self.penalties_count[ip_address] += 1

            return new_score

    def get_mitigation_action(self, ip_address: str) -> str:
        """
        Determine the zero-trust mitigation action for a given IP.

        Args:
            ip_address: The IP address of the host.

        Returns:
            'HARD_ISOLATION', 'RATE_LIMITING', or 'ALLOW'.
        """
        with self.lock:
            score: float = self.trust_scores.get(ip_address, 1.0)
            if score < 0.40:
                return "HARD_ISOLATION"
            elif score < 0.85:
                return "RATE_LIMITING"
            else:
                return "ALLOW"

    def apply_recovery(self, ip_address: str) -> None:
        """
        Gradually increase the trust score of a host by +0.02, capped at 1.0.

        Args:
            ip_address: The IP address of the host.
        """
        with self.lock:
            if ip_address not in self.trust_scores:
                self.trust_scores[ip_address] = 1.0
                return

            old_score: float = self.trust_scores[ip_address]
            new_score: float = min(1.0, old_score + self.recovery_step)
            self.trust_scores[ip_address] = new_score

    def get_all_trust_scores(self) -> Dict[str, float]:
        """
        Get a copy of the current trust scores for all hosts.

        Returns:
            A dictionary mapping IP addresses to their trust scores.
        """
        with self.lock:
            return dict(self.trust_scores)

    def explain_decision(self, ip_address: str) -> Dict[str, Any]:
        """
        Explain the policy decision details for a given IP address.

        Args:
            ip_address: The IP address of the host.

        Returns:
            A dictionary mapping key details of the decision.
        """
        with self.lock:
            score: float = self.trust_scores.get(ip_address, 1.0)
            penalties: int = self.penalties_count.get(ip_address, 0)
            
        action: str = self.get_mitigation_action(ip_address)

        if action == "HARD_ISOLATION":
            reason: str = f"Điểm tin cậy ({score:.2f}) dưới ngưỡng cách ly (0.40)."
        elif action == "RATE_LIMITING":
            reason = f"Điểm tin cậy ({score:.2f}) dưới ngưỡng bóp băng thông (0.85)."
        else:
            reason = f"Điểm tin cậy ({score:.2f}) nằm trong vùng an toàn."

        return {
            'action': action,
            'trust_score': score,
            'last_updated': datetime.datetime.now().isoformat(),
            'penalties_applied': penalties,
            'reason': reason
        }
