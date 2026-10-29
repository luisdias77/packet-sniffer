# packet-sniffer
* Dependências(bibliotecas):

    Para o funcionamento correto do programa, foi necessário utilizar as seguintes bibliotecas:

    * scapy - Para a captura e análise de pacotes

    * argparse - Para a análise de argumentos da linha de comandos

    * json - Para a manipulação de dados em formato JSON, para o registo dos pacotes no ficheiro de log 

    * datetime - Para a manipulação de datas e horas


* Como Selecionar a Interface

    Para selecionar a interface, basta adicionar a flag -i seguida do nome da interface, aquando a execução do programa. 
    
    Exemplo: sudo python3 sniffer.py -i wlo1


* Como ativar filtros e funcionalidades implementadas

    Após a execução do programa com o comando sudo python3 sniffer.py -i wlo1, o programa irá apresentar um menu com as seguintes opções:

       -> live - impressão no terminal
       -> log - impressão num ficheiro
       -> ambos - impressão no terminal e num ficheiro

    Após a seleção do modo, o programa irá apresentar um menu com as seguintes opções:

       1. Capturar TUDO
       2. Filtrar por protocolo
       3. Filtrar por IP (origem ou destino)
       4. Filtrar por MAC (origem ou destino)
       5. Expressão estilo BPF
       6. Analisar ficheiro de log
       7. Ver Estatísticas
       0. Sair

    Após a seleção de uma das opções acima, o programa irá começar a capturar pacotes, dependendo da opção selecionada.

    Existe a possibilidade de interromper a captura de pacotes, pressionando as teclas Ctrl + C, e analisar o ficheiro de log, caso o modo log tenha sido inicialmente escolhido. Nesse ficheiro log, é possivel aplicar filtros, para analisar os pacotes de forma mais detalhada.

    Após interromper a captura temos ainda a possibilidade de ver estatísticas relativas aos pacotes capturados apenas se inicialmente tiver sido escolhido o modo log 
    ou ambos. 


* Execução no Emulador CORE: 

    Comando: sudo python3 sniffer.py -i eth0 (flags - eth0, por exemplo)


* Execução na interface real: 

    Comando: sudo python3 sniffer.py -i wlo1 (flags - wlo1, por exemplo)



* a111474 - Luis Araújo Dias - luisdias77
* a110987 - Gabriel Matos Rodrigues - gabriellrrr
* a110729 - Luís Pedro Matos Machado - luismachado24
