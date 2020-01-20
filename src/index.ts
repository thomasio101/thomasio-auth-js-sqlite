import { Database, open } from 'sqlite';
import { IDatabaseInterface, ISession, Verifier } from 'thomasio-auth-js-common/lib/server';

export type UserFetcher<I, P> = (
	username: string,
	dbPromise: Promise<Database>,
) => Promise<{ storedPassword: P; identity: I } | null>;

export type SessionCreator<I> = (identity: I) => Promise<ISession<I>>;

export class SqliteDatabaseInterface<I, P> implements IDatabaseInterface<I> {
	private dbPromise: Promise<Database>;
	private userFetcher: UserFetcher<I, P>;
	private passwordVerifier: Verifier<P>;
	private sessionCreator: SessionCreator<I>;

	// TODO: Replace identity in userFetcher with a function which fetches the identity.
	constructor(
		dbFileName: string,
		userFetcher: UserFetcher<I, P>,
		passwordVerifier: Verifier<P>,
		sessionCreator: SessionCreator<I>,
	) {
		this.dbPromise = open(dbFileName);
		this.userFetcher = userFetcher;
		this.passwordVerifier = passwordVerifier;
		this.sessionCreator = sessionCreator;
	}

	public async userAuthenticator(
		username: string,
		password: string,
	): Promise<{ valid: true; session: ISession<I> } | { valid: false }> {
		const userFetcherResult = await this.userFetcher(username, this.dbPromise);

		if (userFetcherResult !== null) {
			if (await this.passwordVerifier(userFetcherResult.storedPassword, password)) {
				return {
					session: await this.sessionCreator(userFetcherResult.identity),
					valid: true,
				};
			} else {
				return {
					valid: false,
				};
			}
		} else {
			return {
				valid: false,
			};
		}
	}

	public async sessionAuthenticator(session: ISession<I>) {
		// TODO: Implement SqliteDatabaseInterface.sessionAuthenticator
		return false;
	}
}
