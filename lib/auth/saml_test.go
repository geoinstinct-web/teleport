/*
Copyright 2019-2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/types"
	authority "github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/backend/lite"
	"github.com/gravitational/teleport/lib/fixtures"
	"github.com/gravitational/teleport/lib/services"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
)

func TestCreateSAMLUser(t *testing.T) {
	c := clockwork.NewFakeClockAt(time.Now())
	b, err := lite.NewWithConfig(context.Background(), lite.Config{
		Path:             t.TempDir(),
		PollStreamPeriod: 200 * time.Millisecond,
		Clock:            c,
	})
	require.NoError(t, err)

	clusterName, err := services.NewClusterNameWithRandomID(types.ClusterNameSpecV2{
		ClusterName: "me.localhost",
	})
	require.NoError(t, err)

	authConfig := &InitConfig{
		ClusterName:            clusterName,
		Backend:                b,
		Authority:              authority.New(),
		SkipPeriodicOperations: true,
	}

	a, err := NewServer(authConfig)
	require.NoError(t, err)

	// Create SAML user with 1 minute expiry.
	_, err = a.createSAMLUser(&createUserParams{
		connectorName: "samlService",
		username:      "foo@example.com",
		logins:        []string{"foo"},
		roles:         []string{"admin"},
		sessionTTL:    1 * time.Minute,
	})
	require.NoError(t, err)

	// Within that 1 minute period the user should still exist.
	_, err = a.GetUser("foo@example.com", false)
	require.NoError(t, err)

	// Advance time 2 minutes, the user should be gone.
	c.Advance(2 * time.Minute)
	_, err = a.GetUser("foo@example.com", false)
	require.Error(t, err)
}

func TestEncryptedSAML(t *testing.T) {
	// This Base64 encoded XML blob is a signed SAML response with an encrypted assertion for testing decryption and parsing.
	const EncryptedResponse = `PD94bWwgdmVyc2lvbj0iMS4wIj8+DQo8c2FtbHA6UmVzcG9uc2UgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgSUQ9InBmeDBmNTBiYTg0LWVmNjctNTQyZi1kZDgyLTI4NTU0MzVlMGM4MCIgVmVyc2lvbj0iMi4wIiBJc3N1ZUluc3RhbnQ9IjIwMTQtMDctMTdUMDE6MDE6NDhaIiBEZXN0aW5hdGlvbj0iaHR0cDovL3NwLmV4YW1wbGUuY29tL2RlbW8xL2luZGV4LnBocD9hY3MiIEluUmVzcG9uc2VUbz0iT05FTE9HSU5fNGZlZTNiMDQ2Mzk1YzRlNzUxMDExZTk3Zjg5MDBiNTI3M2Q1NjY4NSI+DQogIDxzYW1sOklzc3Vlcj5odHRwOi8vaWRwLmV4YW1wbGUuY29tL21ldGFkYXRhLnBocDwvc2FtbDpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+DQogIDxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+DQogICAgPGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPg0KICA8ZHM6UmVmZXJlbmNlIFVSST0iI3BmeDBmNTBiYTg0LWVmNjctNTQyZi1kZDgyLTI4NTU0MzVlMGM4MCI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48ZHM6RGlnZXN0VmFsdWU+TUxic3U4WFFOcW4xWE8walUzeHZIL0pPalZnPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5yVTVDUzhWQnZGVjl3RkUvOEY1NHROQTd3UVFWbG9UZkRsL0h1amJwRzJBWTNZcExtdWxzU2pOdngvc0F4a3luZ0lLTVE2dHphZkN3KzZjaGNldzh4bUNOcWdSNWNiQ09DbzB2UUJXaXhINm9jU2FKWDRTU21WeEhhU2p1clRNRkZnamFFYktiM2duV21haGpDb093TU9MZHJtWlprYkp2OWQrWTVUR0VYL2hhUmMvbXU2b05WT3dCL0xMdURDdzk3RTkxdVNUVUpvL1RPS0tVRjJYenZhVEEwMXZobzM5OTYvalpFWkRYR1ZyTGlkOTg5NDJXWWVjT3F6ZnZTWWtLemNaRGd2ZE1udlR1M20yVHpXQ1RqaEVzVDN1cjQ2OThIUmlyZUZTbnFINldhYUVMYjFFeGFiemdxNGFsRG9ma1J3ZU14YWJleVV6aUVBSWhKOGYrNVE9PTwvZHM6U2lnbmF0dXJlVmFsdWU+DQo8ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlES2pDQ0FoS2dBd0lCQWdJUUp0SkRKWlpCa2cvYWZNOGQyWkpDVGpBTkJna3Foa2lHOXcwQkFRc0ZBREJBTVJVd0V3WURWUVFLRXd4VVpXeGxjRzl5ZENCUFUxTXhKekFsQmdOVkJBTVRIblJsYkdWd2IzSjBMbXh2WTJGc2FHOXpkQzVzYjJOaGJHUnZiV0ZwYmpBZUZ3MHhOekExTURreE9UUXdNelphRncweU56QTFNRGN4T1RRd016WmFNRUF4RlRBVEJnTlZCQW9UREZSbGJHVndiM0owSUU5VFV6RW5NQ1VHQTFVRUF4TWVkR1ZzWlhCdmNuUXViRzlqWVd4b2IzTjBMbXh2WTJGc1pHOXRZV2x1TUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF1S0ZMYWYyaUlJL3hEUittMllqNlBuVUVhK3F6cXd4c2RMVWpudW5GWmFBWEcraFptNE1sODBTQ2lCZ0lnVEhRbEp5TElrVHR1Um9INWFlTXl6MUVSVUN0aWk0WnNUcURyampVeWJ4UDRyKzRIVlg2bTM0czZod0VyOEZpZnRzOXBNcDRpUzN0UWd1UmMyOGdQZERvL1Q2VnJKVFZZVWZVVXNORFJ0SXJsQjVPOWlncXFMbnVhWTllcUdpNFBVeDBHMHdSWUpwUnl3b2o4RzBJa3BmUVRpWCtDQUM3ZHQ1d3M3WnJuR3FDTkJMR2k1YkdzYU1tcHRWYnNTRXAxVGVubnRGNTRWMWlSNDlJVjVKcURobTFTMEhta2xlb0p6S2RjKzZzUC94TmVwejlQSnp1RjlkOU51YlRMV2dCc0syOFlJdGNtV0hkSFhEL09EeFZhZWhSandJREFRQUJveUF3SGpBT0JnTlZIUThCQWY4RUJBTUNCNEF3REFZRFZSMFRBUUgvQkFJd0FEQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFBVlU2c05CZGo3NnNhSHdPeEdTZG5FcVFvMnRNdVIzbXNTTTRGNndGSzJVa0tlcHNEN0NZSWYvUHpOU05VcUE1SklFVVZlTXFHeWlIdUFiVTRDNjU1blQxSXlKWDFELytyNzNzU3A1amJJcFFtMnhvUUdabmo2Zy9LbHR3OE9TT0F3K0RzTUYvUExWcW9XSnAwN3U2ZXcvbU54V3NKS2NaNWsrcTRlTXhjaTltS1JISHFzcXVXS1h6UWxVUk1ORkkrbUdhRndyS000ZG16YVIwQkVjK2lsU3hRcVV2UTc0c21zTEsremhOaWttZ2psR0M1b2I5ZzhYa2hWQWtKTUFoMnJiOW9uRE5pUmw2OGlBZ2N6UDg4bVh1dk4vbzk4ZHlwenNQeFhtdzZ0a0RxSVJQVUFVYmg0NjVybFk1c0tNbVJnWGkyclVmbC9RVjVuYm96VW8vSFE9PTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPg0KICA8c2FtbHA6U3RhdHVzPg0KICAgIDxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz4NCiAgPC9zYW1scDpTdGF0dXM+DQogIA0KPHNhbWw6RW5jcnlwdGVkQXNzZXJ0aW9uPjx4ZW5jOkVuY3J5cHRlZERhdGEgeG1sbnM6eGVuYz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjIiB4bWxuczpkc2lnPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIiBUeXBlPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNFbGVtZW50Ij48eGVuYzpFbmNyeXB0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjYWVzMTI4LWNiYyIvPjxkc2lnOktleUluZm8geG1sbnM6ZHNpZz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PHhlbmM6RW5jcnlwdGVkS2V5Pjx4ZW5jOkVuY3J5cHRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNyc2Etb2FlcC1tZ2YxcCIvPjx4ZW5jOkNpcGhlckRhdGE+PHhlbmM6Q2lwaGVyVmFsdWU+TjlLaHFKeWtJdGk1eVZETzdzT0VpT2lMb1VWL2p5aEdITU0wZmFTUzZnWVJ5RUZqaFR2RzNCUEpsd1RTTXpzTTFuY1pwTGVBd0FKaFVzci9mT0pCVGtQbjA3UzZqZGsxYTBMaU9EbjkrcDlCVXlidjRXYWsyWGduMnhXNytDNVQ5bGhvQ0dHRThrdHh6Q0tXL1FhWUNWV3RsMEp1TGdNYWIyWHUzL1dJdVlSWDhKbVZ2ckdPWTlOd0hpeFhFT09PbDFSUUNnbXpNaCtxUno5eFhwWGU0Sk1XRGNqQ0g2blk5V2Fxem4yQTNJVnJzS1V3bUZuTWFaM1lOM04ybmNROWo2QXRYSThoWEErMjBvRlhBQWx2c3JVK0xOek9hTFRzb1QySFZVUER0YldhQm9tS1cxdW9lc1hPZG1KNnVDUVc4Zk9BL3p0QStjL1JERTdyaTZiSFNERCs3YW5uQlNaRzVzL1lrdm5PT2wxRjRFYndLdVpMd3RWdjQza1B1dnRVeUVxTE1HRFlhNmtXczlLRjRsR0dqa0YxMXpqTmVnSTRFd09EVXhZSm14QldRNXhvVm1sOGVvK0VNdGt5NzFGeUttMFhpSGo0cWw5Qnl4dUtaVHJrTXdjQjlPSkNFKzcwM1dpdW5uZy9OSGkrV1IrTmhORlZqUm40SWQ3UTVFTEZZNFRNMklNQld6Y3R2cEd6TGVHdjF2L2RXanVodU1aVjJpeG5nMzRxNXg3VVVnODAwNVlRTnNwOVcwYVZKdDRnY0tUeFAyRnJTVGVjM0MxRktVT1JXSCtVc2ZpZ21GY09YdHFvQXgyK3dDZGs3MkVTS3Z2WFYvWEVFSmd0aTRiVldUK0dzSmc2eGRhTjBPNnlpWTg4eE5BcWZMUEcwajJTb0k1bUcxYzM0YVE9PC94ZW5jOkNpcGhlclZhbHVlPjwveGVuYzpDaXBoZXJEYXRhPjwveGVuYzpFbmNyeXB0ZWRLZXk+PC9kc2lnOktleUluZm8+DQogICA8eGVuYzpDaXBoZXJEYXRhPg0KICAgICAgPHhlbmM6Q2lwaGVyVmFsdWU+a1dWbkpzTkZZZ1JTNlMvTlFERVlsN3RTTjVsTzR6YWtqdXdxTDROMlFHbW9rdnBWRlJreFp3bjVhOXkrVDhLUGZpOWt2bEhlNktzL1I1UTJ2NkdVd0Z4V1dPYVZrOFJDMUh1blN1ZnZ5Tks1Y21hRmJSM0t3OFZZZnNPRVV2T0d6Y2pqTFFjSFFFUEZUMXJsMW0vazc3dExzbFlxV1B6WkRhUFpkU1lkd0kvdlo0OThIeXF3b0Y4U2tCcFVQcW02bnYwVGFVdU5pOWMzbkdDUTBWejE3UGFnLzN3SERWTnA3RlNsSFJlSStySkZsS0RXalF4MStDZjF6U3pjTG5Ecll1aEt3MWY3WVVTYUh0enlBL2l5MkhRMDdSZjRyNUpRaUorR2FOSUkwYk44RTZ0QXJqbjFZSGZWMDRQdWNwa0xDTEJTRndiOERXZE9wMnFEN3pvcEJvc2g2YVF6Vjh3QjhsUEFqUUd2aFhlQVdwRmsxWkVaUG5SRkkydkdkaGFHL2o5TkQvM0EvbzlvZFZpd1ZBdFd4SG9WVzZWcWtLOG5GQlVyL25IVDZTYmdsOFlUd2s4N0hRaldHUEdSaksyNEp3YXc0VjV6djN4bG9zSlFpdnc2dGwyVXk5YWROdUlyOUFCRGJuc3RmdXlQNEZaenR2Q0RTUHFPZlVVQlhya0thczNJRE1iNm9KREQ3a003QVdHcEU5K0lJT0NoVzdiRk5hb3RndHN1OTVqd1ZNQ3BVL0NkNkhPbURrMWpDYVc5RzhlQWJVdjhaUEVmN1Q5c0Z1VnZOaVBVbkFyMWV1VEl6WFNPekFtZk5jdXZpZ1BnOUlCYzAvT0pYWjBBVTgvQWxyRTZRSldwL2pDYThUNTF0YTFjbVN6SGQ4SG0zTEt5aDhsYjljUG5RR3RCeW9LcFUzZEMwQWk3OU1Lc1NhekRTalByY2l6ZUdhS0Vzd1NCTWtWRGtDWFMybGJicXBrckxvN2tMdy9TNG1OMWZCVjU5a2txd1ZlL3pKQXJNNllIckNJUURwRkRCSWtHeXE1WVl1VkQyeXk4YnJmeFNBemMyK2ZpeWQ5OVJndEtTeGZhVkROV3VJZzJnVTRQME40TnVTOCtrb0MzclF6eWovOGdWSlRpSGg5UTFEOVRJbjhjZGllTE12ZlZLT25oMHZBTnR0MDN2YnRHVkJxTTQwa3VLeUxKRWE5TWY0N2xvWk5qamUxd2VvWW1wblZScGVxVGxzUDRzVmwzd3QwYWlDZG5mdHVaVlVWb0M3Um51VDRidVRWZVgybUdNMElxR242czJwZ0xsSU5xVEFTY0F0K3FlVEhycmVTcUhFSmovZnhyM3NySEpyMHZjQ0w2enZZMWtOUi9taGcyL25Bc0hwTkc3c21ITS9oQ3gzOS9HZ01FeFpXbU5lVXV3amhhOHpWc3FRdnZ6cDM3Nk1OWC9xeERuU0JxTEorTERlRXg0SnYweGJxd0tvVE01L3BSQThDOVA4NWRqZXYwT1RKWVBEOGZzNHhabmV6NHRQTlZhcEc1RzEwWG1Wem9TYm1MNXdYamV0bXJJY0NMZ0laeEZnZ1NFSmsxUGFtdThzU2VraHBNOE1EbVZXejZrRDZxdUxyRXNqc0h2K0Rxc1REMkJIRjJMOVVuMjlaL0NvbFBNaDRuT0NRZHpjcjNUT0dEalJaMk1lanJHb2VnblVORW5MaGhwK2luWTB5L2lsODZYV2FweERoUEFLclIxS3pTRUJ5Yk5UUE81S0o4M0pBMGx0dE5JVk9YZ3FkZkQxSy9KYnM4ZHdYY3pRenZCRXBMOXlEZVN4d0wzVXR2VG80NEJLVkYxUVdwUDVvdHU5ZndpZXNkZlJLZm1zM3pteFZiQTZ4dkprK0M2MkE2YXBDcjhqL3FaUldNTUczNytnMUI4bU13eGdabkxyOE9ic2JMQjBVV3JOYWdMbldpc29ZQTVmclcxN21wbW9tc3V1cmhQQ2IrbGczbmFkK1BCRXpXaUZISnJvVkdQMFRwZ1NWZlZvSU9wYkZCS2JpWjVoUnd5YURuaFMrL1UreXNUZ1hXdE1qUk9QYjRROVZiUW8vSXd0NEpVZjZNUlVlN0FoaTNUbTUyOUR5Q1ppOFNydTBtRDF4ZHArdjlkSXF2ZEoxZXROYXZFMTlCSmRDSzN0VHhIZHk2ODh6bEo4NFJOUTlxYzI1R3pudXVFNFg3ZjBkUkQrdEoyNkJNVmh5L3RLeDRzdUpIVURzS05yUmZ4aGM4czNwU2FhUTFZS0E4eVpnQnBIN2tDY0FJZ2g5NlpEU3NuUngzdU5Zc0txakFmd0x3TkNQam02bHY1YVV1azBtYklMelBwMDhFRWFzRWNhWE1CcEZraERKTGhIS1l2WUhPdjlQYTZvWEFOVzZSOC9rSUxoT2ppbnl3RmZUZ2FDci96R20zcitjc2VoM0RxTGNjZjRteXY3Tmp5eERUSWtVeUVDdDJLYnI3S2ZPckh3T3I0L3M0ODVhVVVJVDRxYml5Lzd4U0E1NXlDaFUzV0RkaGpDQ3l2WXNSa3cvUjhVQUMyRExmZWxDVlducWdoTnE3blhNdU9zM3h4L3hpLzE5eEVYK3RxTWNqUHVsc3FQejk4WDF1UE5iZDluYXpSUnFEaXQ2R0Y2NHNlY1ZKVmVjZlpHNTJpTHpRbzZLNzVtdnU0M00rNlI5MkhDdkVWd09sRDhCRWoxYncrUWFaL3FDNVF4UjNtMkR5VHlmd20wVVVUM25yOG0yTDdaR3ozTUU2RXViTzZFWFBVR0JpRnlUeTNNUzRxVGUrbTJoWHdwd0xhTXM3SXFjRVBvMW5KeUJmN1plWm1kZVpsLzJHZ1pVNk94YmxiTmtUZUJORlRWVjhzK0Y2K2h3ZVArMzdBbEVsVWNGNTZaUk9NU0Nmemw0OFRtR1BZNHdpRmlMWGErMXZqTFN6NGdlYzhlVGZJcXczdEdaNjAvUTJGRGV6TUV2MEd0cSsxbTU3VXpqWGtLSVoyNzJBZ3VUNzZsbWUyd1B3dUVtOER2ZHE0Z21ZZlE5MVZ5M3J3aElsVVpvakRxU2R0UHJiTU4zK0JvR1Y0SVFTdUExNlN0UUtJWkg3VVNkckZBZ1dhLzVjQzUwVjIvMUVMMWZRWjJFa01LbktFczRnc2hZNU5YRTYzTmJTSjZiMnpKQll6MDdRcXVTemhycGxUeTR3dVpqcytRd082bUhDZkdEaFY4R2I1RG1HcnExMVVJNVllNVp4RXNLS0FvSlRYdWFOZlRpamFKb2l5L2lvcmFZZk00eUNHUVIyU04wdnc4Zk9LdXA3SlIrejk5TXdmSEJwV21LaHhFM3dITWpZOWpJa3Nyc3JLWnk3MnFRaGROMDZCdEo2SFdpN25PNWJUdHVQZlpmUFdPOFVEZUpKZFdLdUVUNUdpeWFxWGhOM0VwQUQvcDA5RjZkOEgrb1gyRVAzQjRZWXE2cTlSOHpJZG9kZ3cxbncxZjM3MERpL0pSSG1PbnQ5VEord05FS0x5eW42dFVodXRpOGZMY2VKYkk2dHJFb1I2S3NZWGJUeXprVXg5TGtiVkNFelVicVV1YmtrdG5WVm5rcHFJSmNFTGdpZWl0TFRTYW80ZkdOaFROVDVCWDEySWtoQWsrSEhSZlZtWjdhY0lBNDlLYkhlRElpUGxOR3A1WGxMQ1luZGxlOFZlWDF4bEw4Y0duZlB5QWtiSTRLN3RQR2h4S0YzSWFoazFtTVFGWFRhQ3FvdS9pYm9ZQ0F0R3pod3pOaUtLcXhRT2FSWFpQWkY3TlVKbE13NlR1VFhhaU9pM0dLMDZ4eXY2ZEcxTk9ya2daRmhNSS9CZHdjWVcxaHdCaElXWHBVTnpNUyt6cDVTS1BOQW5BSHE4aW16OU1JcGNQajFkYXo0cUNQd3N4dXMwYXBnMkdZQ0xYTW8zdnlTRXd3WTAwQjZzUUlrRHhLTUc4TWtvQjFpMU5vVGMwNnJxTkFOL2szZ3h4UnpBNUFpNHU4NGhpd3dxOXlMWC9oNjFGRnpySklEY3gydHl4MHdUTFd2SzNBWCtOZStQMDZvWWEyVHN4R0RkV0RQR1BFc2U0aFZlTUl6PC94ZW5jOkNpcGhlclZhbHVlPg0KICAgPC94ZW5jOkNpcGhlckRhdGE+DQo8L3hlbmM6RW5jcnlwdGVkRGF0YT48L3NhbWw6RW5jcnlwdGVkQXNzZXJ0aW9uPjwvc2FtbHA6UmVzcG9uc2U+`

	// This XML blob is a sample EntityDescriptor made to satisfy the connector validator for testing.
	const EntityDescriptor = `<?xml version="1.0"?>
	<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2021-02-26T15:57:24Z" cacheDuration="PT1614787044S" entityID="http://some.entity.id">
	  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
		<md:KeyDescriptor use="signing">
		  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
			<ds:X509Data>
			  <ds:X509Certificate>MIIFazCCA1OgAwIBAgIUDpXWZ8npv3sWeCQbB1WCwMoDe9QwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMTAyMTgyMTUyNTVaFw0yMjAyMTgyMTUyNTVaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDiEvFfAwgR8rfFPXVkJiWQGisFQNpQ5oq4ng5sD/3phPBBzwx0TTn+V+XG5pBTlyVe0h9kLqZ3Dnavdk9VDC1DIrc0CSKUhP01JdV9TlC/tCek9a2IQEjEZ0pZPbU/gtXxEGyrs9JVFf0K8saMH6xB8jJwB4Eq9jB8rsWZJh4HeyX1VEdruPdwRkFjuNhBnIax//DQSZepAhtM+mtxP+cHtRzXPlXHTpYvxcP2LoXjSdCh/XEu8Ai33O4Ek14HIFmNQ63pmzmxhpcPm8ejDFchOEU67zeOz2RQNAefeHRgG1gvFIcgmVXcLM+VmC0JlzNuyMFY1XUygm1PYcFz93p4OGJBkYgKifNHPcMzTLQtPoY397WREd/kkMtvgxSDs6GQr2VwByHoo5IoQJ/OpridaDduL9NSc6YHEEXxSceMSdI+txuZvOAJJuLR1DQ5S5xjdHBj8uDsAnmX7oORVadEJ38Aj1UlM+Lk6qnmoBEGAXEfa3Fxyz0qgN9MrtutJO0S4BLqqmXgM9Kulp0B7e7gkRaAyNt/Y0+dAuzYva+uTd7Qm96EEYCTwd9LM4OghTLpDCXFm5EQI+D0zEyOGhDqwQDdx3MHJoPd6xg72ZkoiADY235D/av/ZisF7acPucLvQ41gbWphQgsRTN81lRll/Wgd4EknznXq060RQBkNbwIDAQABo1MwUTAdBgNVHQ4EFgQUzpwOh72T7DyvsvkVV9Cu4YRKBTYwHwYDVR0jBBgwFoAUzpwOh72T7DyvsvkVV9Cu4YRKBTYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEADSc0AEFgMcwArn9zvppOdMlF4GqyJa7mzeVAKHRyXiLm4TSUk8oBk8GgO9f32B5sEUVBnL5FnzEUm7hMAG5DUcMXANkHguIwoISpAZdFh1VhH+13HIOmxre/UN9a1l829g1dANvYWcoGJc4uUtj3HF5UKcfEmrUwISimW0Mpuin+jDlRiLvpvImqxWUyFazucpE8Kj4jqmFNnoOLAQbEerR61W1wC3fpifM9cW5mKLsSpk9uG5PUTWKA1W7u+8AgLxvfdbFA9HnDc93JKWeWyBLX6GSeVL6y9pOY9MRBHqnpPVEPcjbZ3ZpX1EPWbniF+WRCIpjcye0obTTjipWJli5HqwGGauyXPGmevCkG96jiy8nf18HrQ3459SuRSZ1lQD5EoF+1QBL/O1Y6P7PVuOSQev376RD56tOLu1EWxZAmfDNNmlZSmZSn+h5JRcjSh1NFfktIVkHtNPKw8FXDp8098oqrJ3MoNTQgE0vpXiho1QIxWhfaEU5y/WynZFk1PssjBULWNxbeIpOFYk3paNyEpb9cOkOE8ZHOdi7WWJSwHaDmx6qizOQXO75QMLIMxkCdENFx6wWbNMvKCxOlPfgkNcBaAsybM+K0AHwwvyzlcpVfEdaCexGtecBoGkjFRCG+f9InppaaSzmgbIJvkSOMUWEDO/JlFizzWAG8koM=</ds:X509Certificate>
			</ds:X509Data>
		  </ds:KeyInfo>
		</md:KeyDescriptor>
		<md:KeyDescriptor use="encryption">
		  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
			<ds:X509Data>
			  <ds:X509Certificate>MIIFazCCA1OgAwIBAgIUDpXWZ8npv3sWeCQbB1WCwMoDe9QwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMTAyMTgyMTUyNTVaFw0yMjAyMTgyMTUyNTVaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDiEvFfAwgR8rfFPXVkJiWQGisFQNpQ5oq4ng5sD/3phPBBzwx0TTn+V+XG5pBTlyVe0h9kLqZ3Dnavdk9VDC1DIrc0CSKUhP01JdV9TlC/tCek9a2IQEjEZ0pZPbU/gtXxEGyrs9JVFf0K8saMH6xB8jJwB4Eq9jB8rsWZJh4HeyX1VEdruPdwRkFjuNhBnIax//DQSZepAhtM+mtxP+cHtRzXPlXHTpYvxcP2LoXjSdCh/XEu8Ai33O4Ek14HIFmNQ63pmzmxhpcPm8ejDFchOEU67zeOz2RQNAefeHRgG1gvFIcgmVXcLM+VmC0JlzNuyMFY1XUygm1PYcFz93p4OGJBkYgKifNHPcMzTLQtPoY397WREd/kkMtvgxSDs6GQr2VwByHoo5IoQJ/OpridaDduL9NSc6YHEEXxSceMSdI+txuZvOAJJuLR1DQ5S5xjdHBj8uDsAnmX7oORVadEJ38Aj1UlM+Lk6qnmoBEGAXEfa3Fxyz0qgN9MrtutJO0S4BLqqmXgM9Kulp0B7e7gkRaAyNt/Y0+dAuzYva+uTd7Qm96EEYCTwd9LM4OghTLpDCXFm5EQI+D0zEyOGhDqwQDdx3MHJoPd6xg72ZkoiADY235D/av/ZisF7acPucLvQ41gbWphQgsRTN81lRll/Wgd4EknznXq060RQBkNbwIDAQABo1MwUTAdBgNVHQ4EFgQUzpwOh72T7DyvsvkVV9Cu4YRKBTYwHwYDVR0jBBgwFoAUzpwOh72T7DyvsvkVV9Cu4YRKBTYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEADSc0AEFgMcwArn9zvppOdMlF4GqyJa7mzeVAKHRyXiLm4TSUk8oBk8GgO9f32B5sEUVBnL5FnzEUm7hMAG5DUcMXANkHguIwoISpAZdFh1VhH+13HIOmxre/UN9a1l829g1dANvYWcoGJc4uUtj3HF5UKcfEmrUwISimW0Mpuin+jDlRiLvpvImqxWUyFazucpE8Kj4jqmFNnoOLAQbEerR61W1wC3fpifM9cW5mKLsSpk9uG5PUTWKA1W7u+8AgLxvfdbFA9HnDc93JKWeWyBLX6GSeVL6y9pOY9MRBHqnpPVEPcjbZ3ZpX1EPWbniF+WRCIpjcye0obTTjipWJli5HqwGGauyXPGmevCkG96jiy8nf18HrQ3459SuRSZ1lQD5EoF+1QBL/O1Y6P7PVuOSQev376RD56tOLu1EWxZAmfDNNmlZSmZSn+h5JRcjSh1NFfktIVkHtNPKw8FXDp8098oqrJ3MoNTQgE0vpXiho1QIxWhfaEU5y/WynZFk1PssjBULWNxbeIpOFYk3paNyEpb9cOkOE8ZHOdi7WWJSwHaDmx6qizOQXO75QMLIMxkCdENFx6wWbNMvKCxOlPfgkNcBaAsybM+K0AHwwvyzlcpVfEdaCexGtecBoGkjFRCG+f9InppaaSzmgbIJvkSOMUWEDO/JlFizzWAG8koM=</ds:X509Certificate>
			</ds:X509Data>
		  </ds:KeyInfo>
		</md:KeyDescriptor>
		<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
		<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://example.com/saml/acs/example"/>
	  </md:IDPSSODescriptor>
	</md:EntityDescriptor>`

	signingKeypair := &types.AsymmetricKeyPair{
		Cert:       fixtures.TLSCACertPEM,
		PrivateKey: fixtures.TLSCAKeyPEM,
	}

	encryptionKeypair := &types.AsymmetricKeyPair{
		Cert:       fixtures.EncryptionCertPEM,
		PrivateKey: fixtures.EncryptionKeyPEM,
	}

	connector := types.NewSAMLConnector("spongebob", types.SAMLConnectorSpecV2{
		Cert: signingKeypair.Cert,
	})

	connector.SetEntityDescriptor(EntityDescriptor)
	connector.SetIssuer("http://idp.example.com/metadata.php")
	connector.SetSSO("nil")
	connector.SetAssertionConsumerService("http://sp.example.com/demo1/index.php?acs")
	connector.SetSigningKeyPair(signingKeypair)
	connector.SetEncryptionKeyPair(encryptionKeypair)

	clock := clockwork.NewFakeClockAt(time.Date(2021, time.April, 4, 0, 0, 0, 0, time.UTC))
	provider, err := services.GetSAMLServiceProvider(connector, clock)
	require.NoError(t, err)
	assertionInfo, err := provider.RetrieveAssertionInfo(EncryptedResponse)
	require.NoError(t, err)
	require.NotEmpty(t, assertionInfo.Assertions)
}

// TestPingSAMLWorkaround ensures we provide required additional authn query
// parameters for Ping backends (PingOne, PingFederate, etc) when
// `provider: ping` is set.
func TestPingSAMLWorkaround(t *testing.T) {
	// Create a Server instance for testing.
	c := clockwork.NewFakeClockAt(time.Now())
	b, err := lite.NewWithConfig(context.Background(), lite.Config{
		Path:             t.TempDir(),
		PollStreamPeriod: 200 * time.Millisecond,
		Clock:            c,
	})
	require.NoError(t, err)

	clusterName, err := services.NewClusterNameWithRandomID(types.ClusterNameSpecV2{
		ClusterName: "me.localhost",
	})
	require.NoError(t, err)

	authConfig := &InitConfig{
		ClusterName:            clusterName,
		Backend:                b,
		Authority:              authority.New(),
		SkipPeriodicOperations: true,
	}

	a, err := NewServer(authConfig)
	require.NoError(t, err)

	// Create a new SAML connector for Ping.
	const entityDescriptor = `<md:EntityDescriptor entityID="https://auth.pingone.com/8be7412d-7d2f-4392-90a4-07458d3dee78" ID="DUp57Bcq-y4RtkrRLyYj2fYxtqR" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
	<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
		<md:KeyDescriptor use="signing">
		<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
			<ds:X509Data>
			<ds:X509Certificate>MIIDejCCAmKgAwIBAgIGAXnsYbiQMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRYwFAYDVQQKDA1QaW5nIElkZW50aXR5MRYwFAYDVQQLDA1QaW5nIElkZW50aXR5MT8wPQYDVQQDDDZQaW5nT25lIFNTTyBDZXJ0aWZpY2F0ZSBmb3IgQWRtaW5pc3RyYXRvcnMgZW52aXJvbm1lbnQwHhcNMjEwNjA4MTYwODE3WhcNMjIwNjA4MTYwODE3WjB+MQswCQYDVQQGEwJVUzEWMBQGA1UECgwNUGluZyBJZGVudGl0eTEWMBQGA1UECwwNUGluZyBJZGVudGl0eTE/MD0GA1UEAww2UGluZ09uZSBTU08gQ2VydGlmaWNhdGUgZm9yIEFkbWluaXN0cmF0b3JzIGVudmlyb25tZW50MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArqJP+9QA8rzt9lLrKQigkT1HxCP5qIQH9vKgIhCDx5q7eSHOlxQ7MMa+1v1WQq1y5mgNG1zxe+cEaJ646JHQLoa0yj+rXsfCsUsKG7qceHzMR8p4y74x77PHTBJEviS9g/+fMGq7eaSK/F8ksPBfBjHnWv+lvnzrAGhxEuBXfFPf5Gb2Vr5LYurZEu9lIdFtSnFCVjzUIC1SMyovl92K4WdJpZ60N8FUSR6Jb7b8gWjnNHNc1iwr5C2b8+HUuWhqCIc0TQygEilZAdJhpYkeCQMiSqySsV+cmJ1vdjsV0HXX0YREDq6koklnw1hyTe1AckcH6qfWyBcoG2VYORjZPQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQA0eVvkB+/RSIEs7CXje7KKFGO99X7nIBNcpztp6kevxTDFHKsVlGFfl/mkksw9SjzdWSMDgGxxy6riYnScQD0FdyxaKzM0CRFfqdHf2+qVnK4GbiodqLOVp1dDE6CSQuPp7inQr+JDO/xD1WUAyMSC+ouFRdHq2O7MCYolEcyWiZoTTcch8RhLo5nqueKQfP0vaJwzAPgpXxAuabVuyrtN0BZHixO/sjjg9yup8/esCMBB/RR90PxzbI+8ZX5g1MxZZwSaXauQFyOjm5/t+JEisZf8rzrrhDd2GzWrYngB8DJLxCUK1JTM5SO/k3TqeDHLHi202P7AN2S/1CqzCaGb</ds:X509Certificate>
			</ds:X509Data>
		</ds:KeyInfo>
		</md:KeyDescriptor>
		<md:SingleLogoutService Location="https://auth.pingone.com/8be7412d-7d2f-4392-90a4-07458d3dee78/saml20/idp/slo" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"/>
		<md:SingleLogoutService Location="https://auth.pingone.com/8be7412d-7d2f-4392-90a4-07458d3dee78/saml20/idp/slo" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"/>
		<md:SingleSignOnService Location="https://auth.pingone.com/8be7412d-7d2f-4392-90a4-07458d3dee78/saml20/idp/sso" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"/>
		<md:SingleSignOnService Location="https://auth.pingone.com/8be7412d-7d2f-4392-90a4-07458d3dee78/saml20/idp/sso" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"/>
	</md:IDPSSODescriptor>
	</md:EntityDescriptor>`

	signingKeypair := &types.AsymmetricKeyPair{
		Cert:       fixtures.TLSCACertPEM,
		PrivateKey: fixtures.TLSCAKeyPEM,
	}

	encryptionKeypair := &types.AsymmetricKeyPair{
		Cert:       fixtures.EncryptionCertPEM,
		PrivateKey: fixtures.EncryptionKeyPEM,
	}

	connector := types.NewSAMLConnector("ping", types.SAMLConnectorSpecV2{
		AssertionConsumerService: "https://proxy.example.com:3080/v1/webapi/saml/acs",
		Provider:                 "ping",
		Display:                  "Ping",
		AttributesToRoles: []types.AttributeMapping{
			{Name: "groups", Value: "ping-admin", Roles: []string{"admin"}},
		},
		EntityDescriptor:  entityDescriptor,
		SigningKeyPair:    signingKeypair,
		EncryptionKeyPair: encryptionKeypair,
	})

	err = a.UpsertSAMLConnector(context.Background(), connector)
	require.NoError(t, err)

	// Create an auth request that we can inspect.
	req, err := a.CreateSAMLAuthRequest(services.SAMLAuthRequest{
		ConnectorID: "ping",
	})
	require.NoError(t, err)

	// Parse the generated redirection URL.
	parsed, err := url.Parse(req.RedirectURL)
	require.NoError(t, err)

	require.Equal(t, "auth.pingone.com", parsed.Host)
	require.Equal(t, "/8be7412d-7d2f-4392-90a4-07458d3dee78/saml20/idp/sso", parsed.Path)

	// SigAlg and Signature must be added when `provider: ping`.
	require.NotEmpty(t, parsed.Query().Get("SigAlg"), "SigAlg is required for provider: ping")
	require.NotEmpty(t, parsed.Query().Get("Signature"), "Signature is required for provider: ping")
}
