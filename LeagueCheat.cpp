#ifndef ENGINE_H
#define ENGINE_H
#include "LACE.h"
#include "Emulation.h"

// Globals
#define CAMERA_MAX_ZOOM 0xB85178
#define CAMERA_CUR_ZOOM 0xB88968

// Classes
#define CLIENT_PTR 0x2EF30D4 // gPTR_Client VMT
#define TARGET_CLASS 0x2EF6C98
#define MATRIX_DATA 0xE3A00C

// Entities
#define OBJECT_ARRAY 0xE3A564
#define OBJECT_LOCAL 0xE39F6C

template<typename Function >
Function CallVirtual(PVOID pBase, DWORD dwIndex)
{
	PDWORD* VTablePointer = (PDWORD*)pBase;
	PDWORD VTableFunctionBase = *VTablePointer;
	DWORD dwAddress = VTableFunctionBase[dwIndex];

	return (Function)(dwAddress);
}

template<typename T >
T ReadOffset(PVOID pBase, DWORD dwIndex)
{
	return *(T*)((DWORD)pBase + dwIndex);
}

// Every entity is an object including lights, turrets, minions, champions, etc.
class CObject
{
public:
	INT GetTeam()
	{
		return ReadOffset<BYTE >(this, 0x1C);
	}

	BOOL IsMinion()
	{
		if (((GetFlags() >> 11) & 1) == FALSE)
			return FALSE;

		if (IsBadReadPtr(pszObjectName, 0x4) == TRUE)
			return FALSE;

		if (pszObjectName[0] != 'M')
			return FALSE;

		return TRUE;
	}

	BOOL IsTurret()
	{
		return (GetFlags() & 0x2000);
	}

	BOOL IsPlayer()
	{
		return ReadOffset<BYTE >(this, 0x580) == 1;
	}

	BOOL IsAlive()
	{
		return ReadOffset<BYTE >(this, 0x12) == FALSE && GetHealth() > 0;
	}

	D3DXVECTOR3 GetPosition()
	{
		return ReadOffset<D3DXVECTOR3 >(this, 0x70);
	}

	PCHAR GetName()
	{
		return (PCHAR)&pszObjectName;
	}

	PCHAR GetChampion()
	{
		return (PCHAR)&pszChampion;
	}

	FLOAT GetHealth()
	{
		return ReadOffset<FLOAT>(this, 0x128);
	}

	FLOAT GetMaxHealth()
	{
		return ReadOffset<FLOAT>(this, 0x138);
	}

	FLOAT GetMana()
	{
		return ReadOffset<FLOAT>(this, 0x194);
	}

	FLOAT GetMaxMana()
	{
		return ReadOffset<FLOAT>(this, 0x1A4);
	}

	FLOAT GetExtraDamage()
	{
		return ReadOffset<FLOAT>(this, 0x640);
	}

	FLOAT GetBaseDamage()
	{
		return ReadOffset<FLOAT>(this, 0x6A4);
	}

	FLOAT GetDamage()
	{
		return GetBaseDamage() + GetExtraDamage();
	}

	FLOAT GetArmor()
	{
		return ReadOffset<FLOAT>(this, 0x6C0);
	}

	FLOAT GetMagicResist()
	{
		return ReadOffset<FLOAT>(this, 0x6C4);
	}

	FLOAT GetMovementSpeed()
	{
		return ReadOffset<FLOAT>(this, 0x6D4);
	}

	FLOAT GetGold()
	{
		return ReadOffset<FLOAT>(this, 0xE9C);
	}

	DWORD GetFlags()
	{
		return ReadOffset<INT>(this, 0x20);
	}

	FLOAT BaseDamage()
	{
		return ReadOffset<FLOAT>(this, 0x13A0);
	}

	FLOAT AttackRange()
	{
		return ReadOffset<FLOAT>(this, 0x6D8);
	}

	char _unknown0x0[0x2C];
	PCHAR pszObjectName;
	char _unknown0x30[0x4CC];
	PCHAR pszChampion;
};

class CObjectManager
{
public:
	CObject* GetObjectByID(UINT ID)
	{
		return m_pObjectArray[ID];
	}

	DWORD GetHighestIndexUsed()
	{
		return m_dwHighestObjectID;
	}

	CObject** m_pObjectArray; // Array of active objects
	DWORD m_dwMaxObjects; // This is the highest amount of objects the array can store
	DWORD m_dwObjectsUsed; // Total number of objects in use
	DWORD m_dwHighestObjectID; // Highest index of an object actually used
	DWORD m_dwHighestPlayerObjectID; // Highest index in use for a player object
};

class CView
{
public:
	char _unknown0x0[0x18];
	PVOID ThisPtr; // 0x0018
	char _unknown0x1C[0x218];
	INT m_Width; // 0x0234
	INT m_Height; // 0x0238
	char _unknown0x23C[0x110B8];
	INT _unknown0x112F4; // Seems to always be 0
	INT _unknown0x112F8; // Seems to always be 0
	INT m_ResolutionWidth; // 0x112FC
	INT m_ResolutionHeight; // 0x11300
};

class CMatrixData
{
public:
	char _unknown0x0[0x94];
	D3DXMATRIX m_matView; // 0x0094
	D3DXMATRIX m_matProjection; // 0x00D4
};

// =================================================
// Helper Functions
// =================================================
inline CObjectManager* GetObjectManager()
{
	return (CObjectManager*)OBJECT_ARRAY;
}

inline CObject** GetObjectArray()
{
	return *(CObject***)OBJECT_ARRAY;
}

inline CObject* GetLocalEntity()
{
	return *(CObject**)OBJECT_LOCAL;
}

inline CObject* GetObjectByID(UINT ObjectID)
{
	return (GetObjectArray()[ObjectID]);
}

VOID WorldToScreen(D3DXVECTOR3* vecWorld, D3DXVECTOR3* vecScreen)
{
	CView* pView = *(CView**)(0xE3A00C);
	PVOID ThisPtr = pView->ThisPtr;

	D3DVIEWPORT9 viewPort;
	memset(&viewPort, 0, sizeof(viewPort));

	typedef VOID(__thiscall* GetViewportFn)(PVOID, D3DVIEWPORT9*);
	CallVirtual<GetViewportFn >(ThisPtr, 56)(ThisPtr, &viewPort);

	CMatrixData* pMatrixData = *(CMatrixData**)0xE3A00C;

	D3DXMATRIX matWorld;
	memset(&matWorld, 0, sizeof(matWorld));

	D3DXMatrixIdentity(&matWorld);

	D3DXMATRIX matProjection = pMatrixData->m_matProjection;
	D3DXMATRIX matView = pMatrixData->m_matView;

	D3DXVec3Project(vecScreen, vecWorld, &viewPort, &matProjection, &matView, &matWorld);

	vecScreen->x = (vecScreen->x - pView->_unknown0x112F4) / (pView->m_ResolutionWidth - pView->_unknown0x112F4) * pView->m_Width;
	vecScreen->y = (vecScreen->y - pView->_unknown0x112F8) / (pView->m_ResolutionHeight - pView->_unknown0x112F8) * pView->m_Height;
}

#endif // ENGINE_H