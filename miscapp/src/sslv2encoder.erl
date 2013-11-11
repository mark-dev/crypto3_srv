%%%-------------------------------------------------------------------
%%% @author Mark <>
%%% @copyright (C) 2013, Mark
%%% @doc
%%%
%%% @end
%%% Created : 10 Nov 2013 by Mark <>
%%%-------------------------------------------------------------------
-module(sslv2encoder).

-export([encode/1,encode/2]).
-include("sslv2.hrl").

encode(Rec)->
    {PT,Payload} = encode_record(Rec),
    encode_theader(PT,Payload).
-spec encode(Rec :: tuple(),
	     EncryptInfo :: #rsa_encrypt{} | #aes_encrypt{})
	    -> binary() | {State :: term(),binary()}.
encode(Rec,EncryptInfo)->
    {PacketType,Payload} = encode_record(Rec),
    case encrypt(Payload,EncryptInfo) of 
	{NewState,Cipher} ->
	    {NewState,encode_theader(PacketType,Cipher)};
	Cipher ->
	    encode_theader(PacketType,Cipher)
    end.
    
encrypt(Bin,#rsa_encrypt{public = Pub})->
    crypto:public_encrypt(rsa,Bin,Pub,rsa_pkcs1_padding);
encrypt(Bin,#aes_encrypt{state=State}) ->
    {NewState,Cipher} = crypto:stream_encrypt(State,Bin),
    {NewState,Cipher}.


encode_record(#packet_response{code=Code})->
    {?PT_PACKET_RESPONSE,<<Code:8>>};
encode_record(#change_keyspec{public_rsa = [E,N]}) ->
    PubExpBin = integer_to_binary(E),
    ModulusBin = integer_to_binary(N),
    ModulusSize = <<(byte_size(ModulusBin)):16/big>>,
	{?PT_CHANGE_KEY_SPEC,
	 list_to_binary([ModulusSize,ModulusBin,PubExpBin])};
encode_record(#data_transfer_to_client{from=From,
				       content_type=CT,
				       payload=Bin})->
    {?PT_DATA_TRANSFER_TO_CLIENT,
     list_to_binary([<<From:8>>,
		     <<CT:8>>,
		    Bin])};
encode_record(#client_connected{id = ID,login=Login}) ->
    LoginLen = byte_size(Login),
    {?PT_CLIENT_CONNECTED,list_to_binary([<<ID:8>>,<<LoginLen:8>>,Login])};
encode_record(#client_disconnected{id=ID})->
    {?PT_CLIENT_DISCONNECTED,<<ID:8>>};
encode_record(#online_users_response{ids=IDS,logins=Logins})->
    {?PT_ONLINE_USERS_RESPONSE,
     list_to_binary([<<(length(IDS)):8>>,encode_online_users_response(IDS,Logins,<<>>)])};
encode_record(Other)->
    error({encode_record,unknown_clause,[Other]}).

encode_theader(PacketType,Payload)->
    <<?PROTOCOL_LABEL:16/big,
      PacketType:8,
      (byte_size(Payload)):16/big,Payload/binary>>.

encode_online_users_response([],[],Bin)->
    Bin;
encode_online_users_response([ID|IDTail],[Login|LoginTail],Acc) ->
    NewAcc = list_to_binary([Acc,
			     <<ID:8>>,
			     <<(byte_size(Login))>>,
			     Login]),
   encode_online_users_response(IDTail,LoginTail,NewAcc).
    
