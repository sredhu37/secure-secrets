#############################################
# Variables naming convention               #
# o     => object                           #
# s     => string                           #
# by    => bytes                            #
# l     => list                             #
# d     => dictionary                       #
#############################################


from kubernetes import client, config
import getopt, sys
import ssutils


def print_help():
    s_help = """
        Usage:
            kubectl-ssutils.py -n <namespace> -m <method> -e <encryptionsecret> [options]

            -h, --help                  Print help
            -n, --namespace             (required) namespace where the encryption key exists
            -m, --method                (required) method to call; Valid values: encrypt, decrypt
            -e, --encryptionsecret      (required) name of the encryption secret; or an identifiable substring. Example: fernet-key
            -t, --text                  (optional) text to encrypt; Don't use it with -s, --secret
            -s, --secret                (optional) secret to encrypt; or an identifiable substring; Don't use it with -t, --text
    """

    print(s_help)
    exit()

def read_arguments():
    # Remove 1st argument from the list of command line arguments
    l_argumentList = sys.argv[1:]

    # Options
    s_options = "hn:m:e:t:s:"

    # Long options
    l_long_options = ["help", "namespace", "method", "encryptionsecret", "text", "secret"]

    try:
        # Parsing argument
        l_arguments, l_values = getopt.getopt(l_argumentList, s_options, l_long_options)
        d_arguments_result = {}

        # checking each argument
        for s_currentArgument, s_currentValue in l_arguments:
            if s_currentArgument in ("-h", "--help"):
                print_help()
            elif s_currentArgument in ("-n", "--namespace"):
                d_arguments_result["namespace"] = s_currentValue
            elif s_currentArgument in ("-m", "--method"):
                if not s_currentValue in ["encrypt", "decrypt"]:
                    print("Error: Invalid values for <method>!")
                    print_help()
                d_arguments_result["method"] = s_currentValue
            elif s_currentArgument in ("-e", "--encryptionsecret"):
                d_arguments_result["encryptionsecret"] = s_currentValue
            elif s_currentArgument in ("-t", "--text"):
                d_arguments_result["text"] = s_currentValue
            elif s_currentArgument in ("-s", "secret"):
                d_arguments_result["secret"] = s_currentValue

        # Check required arguments
        if "namespace" in d_arguments_result and "method" in d_arguments_result and "encryptionsecret" in d_arguments_result:
            return d_arguments_result
        else:
            print("Error: Missing required argument. Required arguments: namespace, method, encryptionsecret")
            print_help()

    except getopt.error as err:
        # output error, and return with an error code
        print (str(err))
        print_help()

def init_k8s_client():
    global O_K8S_API
    print("Loading kube config...")
    config.load_kube_config()
    O_K8S_API = client.CoreV1Api()
    print("kube config loaded successfully!")


def main():
    d_arguments = read_arguments()
    print(f"Arguments: {d_arguments}")
    init_k8s_client()

    l_secrets_in_namespace = O_K8S_API.list_namespaced_secret(d_arguments["namespace"]).items

    o_cryption_secret, o_fernet_key = ssutils.get_latest_cryption_secret(l_secrets_in_namespace, d_arguments["namespace"], d_arguments["encryptionsecret"])
    # print(f"cryption_secret: {cryption_secret}")

    if "text" in d_arguments:
        # Encrypt the provided text
        if d_arguments["method"] == "encrypt":
            s_encrypted_text = ssutils.encrypt_text(o_fernet_key, d_arguments["text"])
            print(f"Encrypted with key: {o_cryption_secret.metadata.name}; Encrypted value: {s_encrypted_text}")
        elif d_arguments["method"] == "decrypt":
            s_decrypted_text = ssutils.decrypt_text(o_fernet_key, d_arguments["text"])
            print(f"Decrypted value: {s_decrypted_text}")
    elif "secret" in d_arguments:
        # Encrypt the provided secret
        if d_arguments["method"] == "encrypt":
            l_secrets_to_encrypt = list(filter(lambda x: d_arguments["secret"] in x.metadata.name, l_secrets_in_namespace))
            ssutils.encrypt_secrets(o_cryption_secret, o_fernet_key, l_secrets_to_encrypt)
        elif d_arguments["method"] == "decrypt":
            print("To be implemented!")
            pass
    else:
        # Encrypt all secrets in the given namespace
        if d_arguments["method"] == "encrypt":
            ssutils.encrypt_secrets(o_cryption_secret, o_fernet_key, l_secrets_in_namespace)
        elif d_arguments["method"] == "decrypt":
            print("To be implemented!")
            pass


main()

# Commands for testing:
# python3 kubectl-ssutils.py -n jenkins -e fernet-key -m encrypt -t "Hello world!"
# python3 kubectl-ssutils.py -n jenkins -e fernet-key -m decrypt -t "gAAAAABh0X5wMhFbxi6aSmIjR_ftPPMYGTOnfJkxF2Acytpw_8dBF81Ddk6kRB6xSFnfSfnzDRQpVpALRFhbyS3h5q9_bH4J3w=="
# python3 kubectl-ssutils.py -n jenkins -e fernet-key -m encrypt -s default
# python3 kubectl-ssutils.py -n jenkins -e fernet-key -m encrypt
