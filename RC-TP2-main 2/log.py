import json
from datetime import datetime

def ler_ficheiro_log(tipo_de_filtro, valor_do_filtro=""):
    print(f"\n--- A ler os dados do ficheiro log.json [Filtro: {tipo_de_filtro} = {valor_do_filtro if valor_do_filtro else 'Tudo'}] ---")
    
    try:
        with open("log.json", "r") as f:
            for linha in f:
                # Limpa a vírgula, bem como os espaços para o Python conseguir ler o JSON
                dados = json.loads(linha.strip().rstrip(','))
                
                mostrar_pacote = False

                if tipo_de_filtro == "":
                    mostrar_pacote = True
                
                elif tipo_de_filtro == "proto" and valor_do_filtro.lower() == dados['protocolo'].lower():
                    mostrar_pacote = True
                
                elif tipo_de_filtro == "ip" and (valor_do_filtro == dados['ip_origem'] or valor_do_filtro == dados['ip_destino']):
                    mostrar_pacote = True
                
                elif tipo_de_filtro == "mac" and (valor_do_filtro.lower() == dados['mac_origem'].lower() or valor_do_filtro.lower() == dados['mac_destino'].lower()):
                    mostrar_pacote = True
                
                if mostrar_pacote:
                    print(f"{dados['timestamp']} | {dados['protocolo']} | {dados['ip_origem']} -> {dados['ip_destino']} | {dados['resumo']}")
    except:
        print("Erro: O ficheiro log.json não foi encontrado.")


def registar_pacote(dados, modo):
    
    """ 
    Esta função irá receber os dados processados do pacote, vindos do ficheiro analise.py, e irá decidir o que fazer com eles, dependendo do modo selecionado pelo utilizador (live, log, ambos).
    - Se for "live", irá imprimir na consola de forma legível.
    - Se for "log", irá guardar os dados num ficheiro (ex: log.csv ou log.json).
    """

    # print("[Log] A processar a informação final...\n")
    

    # Formato da informação que irá ser impressa na consola 
    informacao_consola = (

        f"[{dados['timestamp']}] Interface:{dados['interface']} | Protocolo: {dados['protocolo']}\n"
        f"   MAC: {dados['mac_origem']}) -> {dados['mac_destino']}\n"
        f"   IP: {dados['ip_origem']} -> {dados['ip_destino']}\n"
        f"   Tamanho: {dados['tamanho']} bytes | Info: {dados['resumo']}\n"

    )

    
    # Modo live, imprimindo na consola, de forma legível
    if modo in ["live", "ambos"]:
        print(informacao_consola)

    
    # Modo log, guardando num ficheiro JSON (log.json) as informações dos pacotes
    if modo in ["log", "ambos"]:

        with open("log.json", "a") as f:
            f.write(json.dumps(dados) + "," +"\n")  # Escreve os dados do pacote em formato JSON, seguido de uma nova linha
    

    
