import argparse
import captura
import log
import json


# Aqui definimos o modo de captura que o utlizador pode selecionar
def modo_captura():
    """
    Função que permite ao utilizador escolher o modo de captura.
    """
    print ("\n" + "="*40)
    print ("  PACKET SNIFFER - CONFIGURAÇÃO INICIAL" )
    print("="*40 + "\n")
    print("Escolha o modo de captura: live, log ou ambos\n")
    print("-> live - impressão no terminal")
    print("-> log - impressão num ficheiro")
    print("-> ambos - impressão no terminal e num ficheiro")
    
    while True:
        modo = input("\nModo: ").lower()
        if modo in ["live", "log", "ambos"]:
            return modo
        print("[!] Modo inválido! Escolha: live, log ou ambos.")


# Aqui definimos o menu de estatísticas, em que o utilizador, dependendo do modo escolhido, pode ver estatísticas
def menu_estatisticas (modo_selecionado):
   

    # Verificamos se o modo escolhido permite ver estatísticas, tem de ser 'log' ou 'ambos'
    if modo_selecionado == "live":
        print("[!] Não é possível ver estatísticas no modo live.")
        print("\n[!] Para ver estatísticas, escolha o modo 'log' ou 'ambos'.")
        return

    # Carregamos os pacotes do ficheiro log.json
    pacotes = []
    try:
        with open("log.json", "r") as f:
           
            # Para cada linha no ficheiro log.json, removemos os espaços em branco e a vírgula no final, para o Python conseguir ler o JSON
            # O .strip() remove os espaços em branco no início e no fim da linha
            # O .rstrip(',') remove a vírgula no final da linha
            for linha in f:
                pacotes.append(json.loads(linha.strip().rstrip(','))) # 
    except Exception as e:
        print(f"\n[!] Erro ao ler ficheiro de log: {e}")
        return
        
    # Se o ficheiro de log estiver vazio, não há dados para analisar
    if not pacotes:
        print("\n[!] O ficheiro de log está vazio. Não há dados para analisar.")
        return
    
    while True:
        print("\n" + "-"*30)
        print("   --- MENU ESTATÍSTICAS ---")
        print("-"*30)
        print("1. Protocolo mais frequente")
        print("2. Top 3 IPs de Destino (quem recebe mais dados)")
        print("3. Volume total de tráfego")
        print("4. Média do tamanho dos pacotes")
        print("5. Voltar ao menu principal")

        opcao = input("\nEscolha uma opção: ")

        # Opção 1: Protocolo mais frequente, conta a frequência de cada protocolo
        if opcao == "1":
            contagem = {}
            for p in pacotes:
                proto = p.get('protocolo', 'Desconhecido')
                contagem[proto] = contagem.get(proto, 0) + 1
            if contagem:
                mais_frequente = max(contagem, key=contagem.get)
                print(f"\n[+] Protocolo mais frequente: {mais_frequente.upper()} ({contagem[mais_frequente]} pacotes)")

        # Opção 2: Top 3 IPs de Destino, conta a frequência de cada IP de destino
        elif opcao == "2":
            destinos = {}
            for p in pacotes:
                
                ip_dst = p.get('ip_destino') or p.get('ip_dst') or "Desconhecido"
                destinos[ip_dst] = destinos.get(ip_dst, 0) + 1
            
            top_3 = sorted(destinos.items(), key=lambda x: x[1], reverse=True)[:3]
            print("\n[+] Top 3 IPs de Destino:")
            for i, (ip, qtd) in enumerate(top_3, 1):
                print(f"  {i}. {ip}: {qtd} pacotes")

        # Opção 3: Volume total de tráfego, soma o campo 'tamanho' de todos os pacotes
        elif opcao == "3":
            total_bytes = sum(p.get('tamanho', 0) or p.get('length', 0) for p in pacotes)
            print(f"\n[+] Volume total de tráfego: {total_bytes} bytes ({total_bytes/1024:.2f} KB)")

        # Opção 4: Média do tamanho dos pacotes, soma o campo 'tamanho' de todos os pacotes e divide pelo número de pacotes
        elif opcao == "4":
            media_bytes = sum(p.get('tamanho', 0) or p.get('length', 0) for p in pacotes) / len(pacotes)
            print(f"\n[+] Média do tamanho dos pacotes: {media_bytes:.2f} bytes")

        # Opção 5: Voltar ao menu principal
        elif opcao == "5":
            break
        else:
            print("[!] Opção inválida!")
            continue

def menu():
    print ("\n" + "="*30)
    print ("  PACKET SNIFFER - MENU" )
    print( "="*30)
    
    print("1. Capturar TUDO")
    print("2. Filtrar por protocolo")
    print("3. Filtrar por IP (origem ou destino)")
    print("4. Filtrar por MAC (origem ou destino)")
    print("5. Expressão estilo BPF")
    print("6. Analisar ficheiro de log")
    print("7. Ver Estatísticas")
    print("0. Sair")
    
    opcao = input("\nEscolha uma opção: ")
    return opcao


def main():
    
    print("=== Packet Sniffer Inicializado ===")

    # Limpa o ficheiro de log antes de começar a nova captura
    try:
        open("log.json", "w").close()
    except Exception as e:
        print(f"[!] Erro ao limpar o log: {e}")
    
    # Prepara o menu de opções da linha de comandos
    parser = argparse.ArgumentParser(description="Packet Sniffer TP2 - Redes de Computadores")
    parser.add_argument("-i", "--interface", help="Interface de rede (ex: eth0, wlan0)", default="todas")
    parser.add_argument("-m", "--modo", choices=["live", "log", "ambos"], help="Modo de operação (ex: live, log, ambos)", default="todos")
     
    # Chama a função modo_captura para obter o modo de captura
    modo_escolhido = modo_captura()

    # Lê o que o utilizador escreveu no terminal
    args = parser.parse_args()
    

    while True: 

        op = menu()
        filtro = ""

        if op == "1":
            filtro = ""
        
        elif op == "2":
            proto = input("Digite o protocolo: ").lower()
            filtro = proto
        
        elif op == "3":
            ip = input("Digite o IP (ex: 10.0.0.1): ")
            filtro = f"host {ip}"
        
        elif op == "4":
            mac = input("Digite o MAC (ex: 00:00:00:00:00:01): ")
            # 'ether host' filtra o MAC tanto em origem como destino
            filtro = f"ether host {mac}"
        
        elif op == "5":
            filtro = input("Digite a expressão BPF: ")
        
        # Opção para parar a captura e analisar o ficheiro de log via terminal
        elif op == "6": 
            print("\n--- Análise do ficheiro de log ---")
            print("Deseja aplicar algum filtro no ficheiro de log?")
            print ("1. Ver tudo")
            print ("2. Filtrar por protocolo")
            print ("3. Filtrar por IP")
            print ("4. Filtrar por MAC")
            
            op_filtro = input("\nEscolha uma opção: ")
            
            if op_filtro == "1":
                
                log.ler_ficheiro_log("", "")
            
            elif op_filtro == "2":

                p = input("Protocolo (ex: icmp): ")
                log.ler_ficheiro_log("proto", p)
            
            elif op_filtro == "3":

                i = input("IP (ex: 10.0.0.1): ")
                log.ler_ficheiro_log("ip", i)
            
            elif op_filtro == "4":

                m = input("MAC (ex: 00:00:00:00:00:01): ")
                log.ler_ficheiro_log("mac", m)
            
            continue
            

        elif op == "7":
            menu_estatisticas(modo_escolhido)
            continue

        elif op == "0":
            print("A encerrar o programa...")
            break
        else:
            print("[!] Opção inválida!")
            continue


        print(f"\n[*] A iniciar o sniffer na interface: {args.interface}")
        print(f"[*] Modo de operação selecionado: {modo_escolhido}\n")
        print(f"[*] Filtro ativo: '{filtro if filtro else 'NENHUM'}'")
        print("[!] Pressiona Ctrl+C para parar e voltar ao menu.")
    
        try: 

            # Chama a captura enviando a interface e o filtro selecionado
            captura.iniciar_captura(args.interface, modo_escolhido, filtro)

        except KeyboardInterrupt:
             print("\n[!] Captura em pausa. A voltar ao menu incial...")
    
if __name__ == "__main__":  
    main()
