import os

rules_dir = r"C:\Users\NITRO 5\Desktop\f_try\malware_scanner\rules"
combined_rules_file = os.path.join(rules_dir, "combined_rules.yar")

with open(combined_rules_file, "w") as outfile:
    for file_name in os.listdir(rules_dir):
        if file_name.endswith(".yar") or file_name.endswith(".yara"):
            with open(os.path.join(rules_dir, file_name), "r") as infile:
                outfile.write(infile.read())
                outfile.write("\n")
print(f"Combined rules saved to {combined_rules_file}")
