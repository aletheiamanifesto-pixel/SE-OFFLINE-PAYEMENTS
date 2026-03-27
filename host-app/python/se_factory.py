"""
se_factory.py — Factory per creare il backend Secure Element appropriato

Questo modulo fornisce un punto di accesso unificato per creare istanze
del Secure Element, scegliendo il backend giusto in base alla configurazione.

Grazie a questa factory, il codice di alto livello non deve sapere
quale implementazione concreta viene usata: basta chiedere il backend
giusto e la factory fornisce l'oggetto corretto.

BACKENDS SUPPORTATI:
  - "simulator": SecureElementSimulator (per sviluppo e test)
  - "pcscard": HardwareSecureElement via PC/SC (per hardware reale)

UTILIZZO:
    from host_app.python.se_factory import create_secure_element

    # In sviluppo
    se = create_secure_element("simulator", initial_balance=10000)

    # In produzione con ACR122U
    se = create_secure_element("pcscard", reader_name="ACS ACR122U", timeout_ms=5000)

UTILIZZO CON PROFILI:
    from host_app.python.se_factory import create_from_profile
    import yaml

    with open("config/hardware_profiles.yaml") as f:
        profiles = yaml.safe_load(f)

    se = create_from_profile(profiles["profiles"]["development"])
"""

from typing import Any

from .se_interface import SecureElementInterface

# Backend supportati (come costanti per evitare errori di battitura)
BACKEND_SIMULATOR = "simulator"
BACKEND_PCSCARD = "pcscard"


def create_secure_element(backend: str, **kwargs: Any) -> SecureElementInterface:
    """
    Crea e restituisce un'istanza di SecureElementInterface per il backend richiesto.

    Parametri:
        backend: il tipo di backend da usare. Valori ammessi:
                 - "simulator": usa il simulatore Python in-memory
                 - "pcscard": usa un lettore PC/SC con smart card fisica
        **kwargs: parametri aggiuntivi specifici del backend:
                  Per "simulator":
                    - initial_balance (int): saldo iniziale in centesimi (default: 10000)
                  Per "pcscard":
                    - reader_index (int): indice del lettore (default: 0)
                    - reader_name (str): nome parziale del lettore (es. "ACR122U")
                    - aid (bytes): AID dell'applet (default: D2760000604101)
                    - timeout_ms (int): timeout in millisecondi (default: 5000)
                    - retries (int): numero di tentativi (default: 3)

    Ritorna:
        Un'istanza di SecureElementInterface pronta all'uso

    Eccezioni:
        ValueError: se il backend non è riconosciuto
        ImportError: se le dipendenze del backend non sono installate (es. pyscard)
        HardwareError: se non si riesce a connettere all'hardware

    Esempi:
        # Simulatore per test
        se = create_secure_element("simulator", initial_balance=5000)

        # Hardware reale con primo lettore disponibile
        se = create_secure_element("pcscard")

        # Hardware reale con lettore specifico
        se = create_secure_element("pcscard", reader_name="ACS ACR122U", retries=5)
    """
    if backend == BACKEND_SIMULATOR:
        return _crea_simulatore(**kwargs)
    elif backend == BACKEND_PCSCARD:
        return _crea_hardware_pcscard(**kwargs)
    else:
        backends_validi = [BACKEND_SIMULATOR, BACKEND_PCSCARD]
        raise ValueError(
            f"Backend '{backend}' non riconosciuto. "
            f"Backend supportati: {backends_validi}"
        )


def create_from_profile(profile: dict) -> SecureElementInterface:
    """
    Crea un SecureElement a partire da un profilo di configurazione.

    I profili sono dizionari che contengono il backend e i suoi parametri,
    tipicamente caricati da config/hardware_profiles.yaml.

    Parametri:
        profile: dizionario con la configurazione del profilo. Deve contenere:
                 - "backend": il tipo di backend (obbligatorio)
                 - altri campi: dipendono dal backend scelto

    Ritorna:
        Un'istanza di SecureElementInterface configurata secondo il profilo

    Eccezioni:
        KeyError: se il profilo non contiene il campo "backend"
        ValueError: se il backend nel profilo non è riconosciuto

    Esempio:
        profile = {
            "backend": "simulator",
            "initial_balance": 10000
        }
        se = create_from_profile(profile)
    """
    if "backend" not in profile:
        raise KeyError(
            "Il profilo deve contenere il campo 'backend'. "
            f"Profilo ricevuto: {profile}"
        )

    backend = profile["backend"]

    # Estrai i parametri specifici del backend (tutto tranne "backend" stesso)
    params = {k: v for k, v in profile.items() if k != "backend"}

    # Conversione di tipi specifici per YAML
    if "aid" in params and isinstance(params["aid"], str):
        params["aid"] = bytes.fromhex(params["aid"])

    return create_secure_element(backend, **params)


def _crea_simulatore(**kwargs: Any):
    """
    Crea un'istanza del simulatore in-memory.

    Parametri accettati:
        initial_balance: saldo iniziale in centesimi (default: 10000 = 100.00€)
    """
    from .se_simulator import SecureElementSimulator

    # Filtra solo i parametri accettati dal simulatore
    initial_balance = kwargs.get("initial_balance", 10000)
    return SecureElementSimulator(initial_balance=initial_balance)


def _crea_hardware_pcscard(**kwargs: Any):
    """
    Crea un'istanza dell'adapter per lettori PC/SC.

    Parametri accettati (vedi HardwareSecureElement.__init__ per i dettagli):
        reader_index, reader_name, aid, timeout_ms, retries
    """
    from .hardware_se import HardwareSecureElement

    # Parametri validi per HardwareSecureElement
    parametri_validi = {"reader_index", "reader_name", "aid", "timeout_ms", "retries"}
    parametri = {k: v for k, v in kwargs.items() if k in parametri_validi}

    return HardwareSecureElement(**parametri)
