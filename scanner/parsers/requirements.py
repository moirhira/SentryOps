from dataclasses import dataclass



@dataclass
class Dependency:
    name: str
    version: str | None
    ecosystem: str
    

def parse_requirements(requirements_file: str) -> list[Dependency]:
    packages = []
    unsupported_operators = {">", "<", ">=", "<=", "~=", "!=", "==="}

    with open(requirements_file, "r") as file:
        for line in file:
            line = line.strip() 

            if not line or line.startswith("#"):
                continue

            if line.startswith(("git+", "-r", "--", "-e")):
                print(f"Warning: Unsupported line in requirements file: {line}. This package will be ignored.")
                continue


            if "==" in line:
                package, version = line.split("==", 1)
                packages.append(Dependency(name=package, version=version, ecosystem="PyPI"))
                continue

            if any(op in line for op in unsupported_operators):
                print(f"Warning: Unsupported operator found in line: {line}. This package will be ignored.")
                continue
            
            
            packages.append(Dependency(name=line, version=None, ecosystem="PyPI"))

    return packages
