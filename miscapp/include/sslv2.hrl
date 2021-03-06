-define(PT_PACKET_RESPONSE,1).
-define(PT_CONN_REQUEST,2).
-define(PT_CHANGE_KEY_SPEC,3).
-define(PT_SERVER_CHANGE_KEY_SPEC,4).
-define(PT_AUTH_PACKET,5).
-define(PT_DATA_TRANSFER,6).
-define(PT_GET_ONLINE_USERS,7).
-define(PT_CLIENT_CONNECTED,8).
-define(PT_CLIENT_DISCONNECTED,9).
-define(PT_AES_KEY,10).
-define(PT_ONLINE_USERS_RESPONSE,12).
-define(PT_DATA_TRANSFER_TO_CLIENT,13).
-define(PT_CLIENT_WANT_CHANGE_KEYSPEC,14).

-define(CHANGE_KEYSPEC_REASON_TTL,1).

-define(CONTENT_TYPE_TEXT,2).
-define(CONTENT_TYPE_IMAGE,3).

-define(PROTOCOL_LABEL,42134).

-define(PACKET_RESPONSE_OK,1).
-define(PACKET_RESPONSE_FAIL,2).

%% PROTOCOL
-record(theader,{packet_type :: integer(),
		 payload :: binary() | tuple()}).
-record(packet_response,{code :: integer()}).
-record(change_keyspec,{public_rsa :: crypto:rsa_public()}).
-record(conn_request,{cert :: binary()}).
-record(server_change_keyspec,{reason :: integer()}).
-record(client_want_change_keyspec,{reason :: integer()}).

-record(auth_packet,{login :: bitstring(),
		     password :: binary()}).
-record(data_transfer,{recipient :: integer(),
		       content_type :: integer(),
		       payload :: binary()}).
-record(data_transfer_to_client,{from :: integer(),
				 content_type :: integer(),
				 payload :: binary()}).
-record(get_online_users,{}).
-record(aes_key,{key :: binary()}).

-record(online_users_response,{ids :: [integer()],
			      logins :: [bitstring()]
			      }).
-record(client_connected,{id :: integer(),
			  login :: bitstring()}).

-record(client_disconnected,{id :: integer()}).

%% INTERNAL
-record(rsa_decrypt,{private :: crypto:rsa_private()}).
-record(aes_decrypt,{state}).

-record(rsa_encrypt,{public :: crypto:rsa_public()}).
-record(aes_encrypt,{state}).
