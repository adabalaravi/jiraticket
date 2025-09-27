# Intentionally insecure Python code for Snyk Code to flag
import pickle, subprocess

def insecure_eval(user_input: str):
    return eval(user_input)  # insecure

def insecure_pickle(data: bytes):
    return pickle.loads(data)  # insecure

def run_shell(cmd: str):
    return subprocess.check_output(cmd, shell=True)  # insecure

if __name__ == '__main__':
    expr = input('Enter expression: ')
    print(insecure_eval(expr))
