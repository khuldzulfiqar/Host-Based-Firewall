import json

class RuleEngine:
    def __init__(self, rules_file="rules.json"):
        self.rules_file = rules_file
        self.rules = self.load_rules()

    def load_rules(self):
        try:
            with open(self.rules_file, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return []

    def match_rule(self, packet):
        # Go through all rules
        for rule in self.rules:
            proto = rule.get("protocol", "").lower()
            dst_port = rule.get("dst_port")
            action = rule.get("action", "allow").lower()

            # Match protocol and destination port
            if packet.protocol.lower() == proto and packet.dst_port == dst_port:
                return action
        return "allow"  # default action

    def add_rule(self, new_rule):
        self.rules.append(new_rule)
        with open(self.rules_file, "w") as f:
            json.dump(self.rules, f, indent=4)
