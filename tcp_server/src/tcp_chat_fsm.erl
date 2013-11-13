-module(tcp_chat_fsm).
-author('mark-peres').

-behaviour(gen_fsm).

-export([start_link/0, set_socket/2]).
-export([init/1, handle_event/3,
         handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).

%% Состояния FSM
-export([
	 wait_for_socket/2,
	 wait_for_change_cihper/2,
	 wait_for_aes_key/2,
	 wait_for_conn_request/2,
	 wait_for_auth/2,	 
	 ready_for_requests/2
	]).
-include("../../miscapp/include/sslv2.hrl").

-record(state, {
	  socket,    %% Клиентский сокет
	  addr,      %% Адресс клиента
	  encrypt_info, %% Как кодируем
	  decrypt_info, %% Как декодируем
	  user_id :: integer(),
	  user_login :: binary(),
	  tref %%timer reference
	 }).

-define(TIMEOUT, 120000).
-define(KEY_TTL,20000).
-define(log(S,R),error_logger:info_msg("[~p] ~p: " ++ S,[self(),?MODULE] ++ R)).
-define(log(S),error_logger:info_msg("[~p] ~p: " ++ S,[self(),?MODULE])).
%% ------------------------------------------------------------------------
%% API
%% ------------------------------------------------------------------------

%%-------------------------------------------------------------------------
%% @spec (Socket) -> {ok,Pid} | ignore | {error,Error}
%% @doc To be called by the supervisor in order to start the server.
%%      If init/1 fails with Reason, the function returns {error,Reason}.
%%      If init/1 returns {stop,Reason} or ignore, the process is
%%      terminated and the function returns {error,Reason} or ignore,
%%      respectively.
%% @end
%%-------------------------------------------------------------------------
start_link() ->
    gen_fsm:start_link(?MODULE, [], []).

set_socket(Pid,Socket) when is_pid(Pid), is_port(Socket) ->
    gen_fsm:send_event(Pid, {socket_ready, Socket}).

%%------------------------------------------------------------------------
%% Callback functions from gen_server
%%------------------------------------------------------------------------

%%-------------------------------------------------------------------------
%% Func: init/1
%% Returns: {ok, StateName, StateData}          |
%%          {ok, StateName, StateData, Timeout} |
%%          ignore                              |
%%          {stop, StopReason}
%% @private
%%-------------------------------------------------------------------------
init([]) ->
    process_flag(trap_exit, true),
    {ok, wait_for_socket, #state{}}.

%%
%% WAIT_FOR_SOCKET
%%
wait_for_socket({socket_ready, Socket}, State) when is_port(Socket) ->
    %% Новое подключение
    inet:setopts(Socket, [{active, once},binary,{reuseaddr, true}]),
    {ok, {IP, _Port}} = inet:peername(Socket),
    error_logger:info_msg("[~p] ~p : wait_for_socket new client"
			  "->wait_for_change_cipher ~n",[self(),?MODULE]),
    {next_state,wait_for_change_cihper, State#state{socket=Socket, addr=IP}, ?TIMEOUT}.

%%
%% WAIT_FOR_CHANGE_CIPHER - ОЖИДАЕТ RSA ключ клиента
%%
wait_for_change_cihper({data, Data}, #state{socket=S} = State) ->
    #change_keyspec{public_rsa = ClientPub} = sslv2decoder:decode(Data),
    {ServPub,ServPriv} = erl_make_certs_wrap:gen_key(128),
    Reply = #change_keyspec{public_rsa = ServPub},
    reply(S,Reply),
    ?log("RSA key exchange finished ~n"),
    {next_state,wait_for_aes_key,State#state{decrypt_info = #rsa_decrypt{private = ServPriv},
					     encrypt_info = #rsa_encrypt{public = ClientPub}}}.
%%
%% WAIT_FOR_AES_KEY - Ожидает AES ключ от клиента
%%
wait_for_aes_key({data, Data}, #state{socket=S,
				      decrypt_info=DI} = State) ->
    #aes_key{key=AesKey} = sslv2decoder:decode(Data,DI),
    AESState = crypto:stream_init(aes_ctr, AesKey, AesKey),
    Reply = #packet_response{code=?PACKET_RESPONSE_OK},
    reply(S,Reply,#aes_encrypt{state=AESState}),
    TRef = create_key_ttl_timer(?KEY_TTL),
    {next_state,wait_for_conn_request,State#state{decrypt_info = #aes_decrypt{state=AESState},
						  encrypt_info = #aes_encrypt{state=AESState},						 		tref = TRef}}.

%%
%% WAIT_FOR_CONN_REQUEST - ожидает сертификат клиента
%%
wait_for_conn_request({data, Data}, #state{socket=S,
					   encrypt_info = EI,
					   decrypt_info = DI} = State) ->
    {_AESState1,#conn_request{cert=Bin}} = sslv2decoder:decode(Data,DI),
    {ReplyCode,NewState} = case is_cert_valid(Bin) of
			       true ->
				   {?PACKET_RESPONSE_OK,wait_for_auth};
			       false ->
				   {?PACKET_RESPONSE_FAIL,wait_for_conn_request}
			   end,
    Reply = #packet_response{code=ReplyCode},
    {save_aes_state,_NewAESState} = reply(S,Reply,EI),
    {next_state,NewState,State
%#state{encrypt_info = #aes_encrypt{state=NewAESState},
%				     decrypt_info = #aes_decrypt{state=NewAESState}}
}.

%%
%% WAIT_FOR_AUTH - ожидает логин пароль от клиента
%%
wait_for_auth({data,Data},#state{socket=S,
				 encrypt_info = EI,
				 decrypt_info = DI} = State)->
    {_,#auth_packet{login = Login,password = Password}} = sslv2decoder:decode(Data,DI),
    {ReplyCode,NewState,ClientID,ClientLogin} = 
	case ets_mgr:is_auth_valid(Login,Password) of
	    {true,CliID} ->
		?log("auth_valid -> client id = ~p ~n",[CliID]),
		ets_mgr:client_connected(CliID,Login,self()),
		broadcast_that_client_connected(CliID,Login),
		{?PACKET_RESPONSE_OK,ready_for_requests,CliID,Login};
	    false ->
		?log("auth not valid(~p,~p)",[Login,Password]),
		{?PACKET_RESPONSE_FAIL,wait_for_auth,undefined,undefined}
	end,
    Reply = #packet_response{code=ReplyCode},
    reply(S,Reply,EI),
    {next_state,NewState,State#state{ user_id = ClientID, user_login = ClientLogin}}.

%%
%% READY_FOR_REQUESTS - обрабатывает запросы
%%

ready_for_requests({data,Data},#state{socket=S,
				      user_id = UserId,
				      tref = TRef,
				      encrypt_info = EI,
				      decrypt_info = DI} = State) ->
    {_,Plain} = sslv2decoder:decode(Data,DI),
    {Reply,NewState} = case Plain of
			    #get_online_users{} ->
				{Ids,Logins} = ets_mgr:get_online_users(),
				{#online_users_response{ids = Ids,logins = Logins},
				 State};
			    #data_transfer{} = DT ->
				notify_about_new_msgs(UserId,DT),
				{#packet_response{code = ?PACKET_RESPONSE_OK},
				 State};
			    #aes_key{key=NewAesKey} ->
			       cancel_key_ttl_timer(TRef),
			       ?log("Got new AES key from client"),
			       AESState = crypto:stream_init(aes_ctr, NewAesKey, NewAesKey),
			       NewTRef = create_key_ttl_timer(?KEY_TTL),
				{noreply,
				 State#state{encrypt_info = #aes_encrypt{state=AESState},
					     tref = NewTRef,
					     decrypt_info = #aes_decrypt{state=AESState}}};
			    Other ->
				?log("unknown RX when ready_for_requests ~p ~n",[Other]),
				{#packet_response{code = ?PACKET_RESPONSE_FAIL},
				 State}
			end,
    Reply /= noreply andalso reply(S,Reply,EI),
    {next_state,ready_for_requests,NewState}.
reply(Socket,Data) when is_binary(Data) ->
    ?log("TX: ~p ~n",[Data]),
    gen_tcp:send(Socket,Data);
reply(Socket,Data) when is_tuple(Data) ->
    reply(Socket,sslv2encoder:encode(Data)).

reply(Socket,Record,CryptInfo) when is_tuple(Record),is_tuple(CryptInfo)->
    case sslv2encoder:encode(Record,CryptInfo) of
	{State,Bin} ->
	    reply(Socket,Bin),
	    {save_aes_state,State};
	Bin ->
	    reply(Socket,Bin)
    end.




handle_info({tcp, Socket, Bin}, StateName, #state{socket=Socket} = StateData) ->
    ?log("RX: ~p ~n",[Bin]),
    inet:setopts(Socket, [{active, once}]),
    ?MODULE:StateName({data, Bin}, StateData);

%% Клиент отключился
handle_info({tcp_closed, Socket}, _StateName,#state{socket=Socket} = State) ->
    {stop, normal, State};
handle_info(key_ttl_expired,StateName,#state{socket=S,encrypt_info = EI} = State) ->
    reply(S,#server_change_keyspec{reason = ?CHANGE_KEYSPEC_REASON_TTL},EI),
    {next_state,StateName,State};
%% Кто-то написал новое сообщение твоему клиенту, отправь его.
handle_info({send_it,Record},StateName,#state{socket=S,
					      encrypt_info = EI}=State) ->
    reply(S,Record,EI),
    {next_state,StateName,State};

handle_info(Info, StateName, StateData) ->
    error_logger:info_msg("[~p],~p : handle_info with ~p ~n",[self(),?MODULE,Info]),
    ?MODULE:StateName(Info, StateData).
%%
%% other gen_fsm callbacks
%%
handle_event(Event, StateName, StateData) ->
    {stop, {StateName, undefined_event, Event}, StateData}.

handle_sync_event(Event, _From, StateName, StateData) ->
    {stop, {StateName, undefined_event, Event}, StateData}.

terminate(_Reason, _StateName, #state{socket=Socket,
				      user_id = UserId,
				      user_login = Login}) ->
    (catch gen_tcp:close(Socket)),
    (catch broadcast_that_client_disconnected(UserId)),
    (catch ets_mgr:client_disconnected(UserId,Login,self())),
    ok.

code_change(_OldVsn, StateName, StateData, _Extra) ->
    {ok, StateName, StateData}.


is_cert_valid(_Bin)->
    true.

broadcast_all(Message)->
    OtherUsersPid = ets_mgr:get_all_online_pid(self()),
    lists:foreach(fun(Pid) ->
			  Pid ! Message
		  end,OtherUsersPid).
broadcast_that_client_connected(CliID,Login)->
    ?log("broadcast client connected: {~p,~p} ~n",[CliID,Login]),
    broadcast_all({send_it,#client_connected{id = CliID,login = Login}}).

broadcast_that_client_disconnected(CliID) ->
    ?log("broadcast client disconnected: ~p ~n",[CliID]),
    broadcast_all({send_it,#client_disconnected{id = CliID}}).

notify_about_new_msgs(From,#data_transfer{recipient=ToID,
					  content_type=CT,
					  payload = Payload})->
    case ets_mgr:pid_by_user_id(ToID) of
	{ok,Pid} ->
	    Pid ! {send_it,#data_transfer_to_client{from = From,
						    content_type = CT,
						    payload = Payload}};
	{error,not_found} ->
	    error_logger:info_msg("Pid for clientID = ~p not found" ,[ToID])
    end.

cancel_key_ttl_timer(TRef)->
    erlang:cancel_timer(TRef).

create_key_ttl_timer(Timeout)->
    erlang:send_after(Timeout,self(),key_ttl_expired).
